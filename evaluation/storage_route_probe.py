"""Direct signed bucket HEAD correlated with the selected server's accepted socket."""
import http.client
import ipaddress
import os
from pathlib import Path
import re
import ssl


def address(raw, family):
    value = bytes.fromhex(raw)
    if len(value) != (4 if family == 4 else 16):raise ValueError('TCP address layout')
    value = value[::-1] if family == 4 else b''.join(value[i:i+4][::-1] for i in range(0, 16, 4))
    result = ipaddress.ip_address(value)
    if isinstance(result, ipaddress.IPv6Address) and result.ipv4_mapped:result = result.ipv4_mapped
    return result


def accepted_inodes(proc, pid, server, client, listener):
    matches = set()
    for family, name in ((4, 'tcp'), (6, 'tcp6')):
        lines = listener['read_bounded'](proc / str(pid) / 'net' / name, 2 * 1024 * 1024).splitlines()
        if not lines or 'local_address' not in lines[0]:raise ValueError('TCP table layout')
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10:raise ValueError('TCP table layout')
            if fields[3] != '01':continue
            local, local_port = fields[1].split(':');remote, remote_port = fields[2].split(':')
            if ((address(local, family), int(local_port, 16)) == server
                    and (address(remote, family), int(remote_port, 16)) == client):
                matches.add(int(fields[9]))
    if len(matches) != 1:raise ValueError('Accepted connection missing or ambiguous')
    owners = set();total = 0
    processes = [p for p in proc.iterdir() if p.name.isdecimal()]
    if len(processes) > 4096:raise ValueError('Connection owner census limit')
    for process in processes:
        with os.scandir(process / 'fd') as descriptors:
            count = 0
            for descriptor in descriptors:
                count += 1;total += 1
                if count > 4096 or total > 32768:raise ValueError('Connection FD census limit')
                target = os.readlink(descriptor.path)
                match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
                if match and int(match[1]) in matches:owners.add(int(process.name))
    if owners != {pid}:raise ValueError('Accepted connection owner mismatch')
    return next(iter(matches))


def observe_route(config, pid, listener, signing, *, proc=Path('/proc')):
    """Numeric direct origin only; held keep-alive connection avoids stale socket attribution."""
    parsed = signing['urllib'].parse.urlsplit(config['endpoint'])
    expected = ipaddress.ip_address(parsed.hostname)
    if isinstance(expected, ipaddress.IPv6Address) and expected.ipv4_mapped:expected = expected.ipv4_mapped
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    network = os.stat(proc / str(pid) / 'ns/net');own = os.stat(proc / 'self/ns/net')
    if (network.st_dev, network.st_ino) != (own.st_dev, own.st_ino):
        raise ValueError('Direct peer network namespace mismatch')
    connection = (http.client.HTTPSConnection(parsed.hostname, port, timeout=5, context=ssl.create_default_context())
                  if parsed.scheme == 'https' else http.client.HTTPConnection(parsed.hostname, port, timeout=5))
    try:
        connection.connect()
        server_tuple = connection.sock.getpeername()[:2];client_tuple = connection.sock.getsockname()[:2]
        server = (ipaddress.ip_address(server_tuple[0]), server_tuple[1])
        client = (ipaddress.ip_address(client_tuple[0]), client_tuple[1])
        if server != (expected, port):raise ValueError('Direct peer origin mismatch')
        path = '/' + config['bucket']
        timestamp = signing['datetime'].now(signing['timezone'].utc).strftime('%Y%m%dT%H%M%SZ')
        headers = signing['signed_headers'](config, 'HEAD', path, '', b'', timestamp)
        headers['Connection'] = 'keep-alive'
        connection.request('HEAD', path, headers=headers)
        response = connection.getresponse()
        if response.status != 200 or response.will_close:
            raise ValueError('Bound bucket keep-alive response unavailable')
        inode = accepted_inodes(proc, pid, server, client, listener)
        response.read(1)
        return dict(outcome='direct_peer_connection_observed', accepted_socket_inode=inode,
                    net_namespace_device=network.st_dev, net_namespace_inode=network.st_ino,
                    pid=pid, address=str(expected), port=port)
    finally:connection.close()
