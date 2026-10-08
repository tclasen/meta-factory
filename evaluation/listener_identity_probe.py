"""Bound a selected Linux process executable to its observed listening socket.

Formats: https://docs.kernel.org/networking/proc_net_tcp.html
https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
No process environments, command lines, file paths or unrelated FD targets are emitted.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time


class IdentityIncomplete(Exception):
    def __init__(self, code):self.code = code


def read_bounded(path, limit):
    with path.open('rb') as stream:raw = stream.read(limit + 1)
    if len(raw) > limit:raise IdentityIncomplete('proc_read_limit')
    return raw.decode('ascii')


def process_start(path, pid):
    raw = read_bounded(path / 'stat', 8192)
    suffix = raw.rsplit(')', 1)[1].split()
    if (raw.split(' ', 1)[0] != str(pid) or len(suffix) < 20
            or suffix[0] not in ('R', 'S', 'D', 'T', 't', 'W', 'K', 'P', 'I')
            or not re.fullmatch(r'[0-9]{1,24}', suffix[19])):
        raise IdentityIncomplete('process_identity_unavailable')
    return suffix[19]


def local_addresses(proc):
    import fcntl
    addresses = set()
    interfaces = socket.if_nameindex()
    if len(interfaces) > 1024:raise IdentityIncomplete('interface_limit')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        for _, name in interfaces:
            try:
                packed = fcntl.ioctl(channel.fileno(), 0x8915, struct.pack('256s', name.encode()[:15]))
                addresses.add(ipaddress.ip_address(packed[20:24]))
            except OSError:
                continue
    for line in read_bounded(proc / 'net/if_inet6', 131072).splitlines():
        fields = line.split()
        if len(fields) != 6:raise IdentityIncomplete('interface_layout')
        addresses.add(ipaddress.ip_address(bytes.fromhex(fields[0])))
    return addresses


def socket_rows(path, family):
    rows = []
    lines = read_bounded(path, 2 * 1024 * 1024).splitlines()
    if not lines or 'local_address' not in lines[0]:raise IdentityIncomplete('socket_table_layout')
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:raise IdentityIncomplete('socket_table_layout')
        if fields[3] != '0A':continue
        host, port = fields[1].split(':')
        raw = bytes.fromhex(host)
        if len(raw) != (4 if family == 4 else 16):raise IdentityIncomplete('socket_address_layout')
        raw = raw[::-1] if family == 4 else b''.join(raw[i:i+4][::-1] for i in range(0, 16, 4))
        address = ipaddress.ip_address(raw)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:address = address.ipv4_mapped
        rows.append((address, int(port, 16), int(fields[9]), int(fields[7])))
    return rows


def observe(pid, start_ticks, expected_sha256, address, port, *, proc=Path('/proc'), addresses=None):
    if (type(pid) is not int or not 1 <= pid <= 2147483647 or not re.fullmatch(r'[0-9]{1,24}', start_ticks)
            or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256) or type(port) is not int or not 1 <= port <= 65535):
        raise ValueError('Bounded selected process identity required')
    requested = ipaddress.ip_address(address)
    if isinstance(requested, ipaddress.IPv6Address) and requested.ipv4_mapped:requested = requested.ipv4_mapped
    if not (requested.is_private or requested.is_loopback) or requested.is_link_local or requested.is_multicast or requested.is_unspecified:
        raise ValueError('Bound internal listener required')
    started, wall_started = time.monotonic(), time.time()
    def deadline():
        if max(time.monotonic()-started, time.time()-wall_started) >= 35:
            raise IdentityIncomplete('identity_deadline')
    process = proc / str(pid)
    def snapshot():
        deadline()
        if process_start(process, pid) != start_ticks:raise IdentityIncomplete('process_start_mismatch')
        network = os.stat(process / 'ns/net')
        own_network = os.stat(proc / 'self/ns/net')
        same_network = (network.st_dev, network.st_ino) == (own_network.st_dev, own_network.st_ino)
        assigned = addresses if addresses is not None else (local_addresses(proc) if same_network else set())
        matches = []
        for row in socket_rows(process / 'net/tcp', 4) + socket_rows(process / 'net/tcp6', 6):
            host, actual_port, inode, uid = row
            if actual_port != port:continue
            if host.is_unspecified and host.version == 6 and requested.version == 4:
                raise IdentityIncomplete('cross_family_wildcard_ambiguous')
            match = host == requested or (host.is_unspecified and host.version == requested.version
                    and same_network and (requested.is_loopback or requested in assigned))
            if match:matches.append((str(host), inode, uid))
        if not 1 <= len(matches) <= 16:raise IdentityIncomplete('listener_missing_or_ambiguous')
        inodes = {entry[1] for entry in matches}
        owners = {inode:set() for inode in inodes}
        processes = [entry for entry in proc.iterdir() if entry.name.isdecimal()]
        if len(processes) > 4096:raise IdentityIncomplete('process_census_limit')
        fd_count = 0
        for candidate in processes:
            deadline()
            try:
                # Hold the directory open while reading self-FDs, avoiding a stale
                # entry for the scanner's own already-closed directory descriptor.
                with os.scandir(candidate / 'fd') as descriptors:
                    candidate_count = 0
                    for descriptor in descriptors:
                        candidate_count += 1;fd_count += 1
                        if candidate_count > 4096 or fd_count > 32768:
                            raise IdentityIncomplete('fd_census_limit')
                        try:target = os.readlink(descriptor.path)
                        except FileNotFoundError:raise IdentityIncomplete('fd_census_changed')
                        matched = re.fullmatch(r'socket:\[([0-9]+)\]', target)
                        if matched and int(matched[1]) in owners:owners[int(matched[1])].add(int(candidate.name))
            except FileNotFoundError:raise IdentityIncomplete('process_census_changed')
        if any(value != {pid} for value in owners.values()):raise IdentityIncomplete('listener_shared_or_wrong_owner')
        boot = hashlib.sha256(read_bounded(proc / 'sys/kernel/random/boot_id', 128).encode()).hexdigest()
        return dict(pid=pid, process_start_ticks=start_ticks, boot_id_sha256=boot,
                    net_namespace_device=network.st_dev, net_namespace_inode=network.st_ino,
                    listener_rows=sorted(matches), same_network_namespace=same_network)
    before = snapshot()
    descriptor = os.open(process / 'exe', os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        first = os.fstat(stream.fileno())
        if not stat.S_ISREG(first.st_mode) or not 0 < first.st_size <= 256 * 1024 * 1024:
            raise IdentityIncomplete('executable_size_or_type')
        digest = hashlib.sha256();count = 0
        while True:
            deadline();chunk = stream.read(65536)
            if not chunk:break
            count += len(chunk)
            if count > 256 * 1024 * 1024:raise IdentityIncomplete('executable_size_or_type')
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(first, key) != getattr(after, key) for key in fields):
            raise IdentityIncomplete('executable_changed')
        if digest.hexdigest() != expected_sha256:raise IdentityIncomplete('executable_digest_mismatch')
        named = os.stat(process / 'exe')
        if any(getattr(after, key) != getattr(named, key) for key in fields):
            raise IdentityIncomplete('executable_changed')
    if before != snapshot():raise IdentityIncomplete('listener_identity_changed')
    deadline()
    return dict(before, outcome='listener_identity_observed', executable_sha256=expected_sha256,
                exclusive_owner_snapshots=True, snapshot_stable=True, provider_semantics_verified=False,
                response_route_verified=False, runtime_memory_verified=False)


if __name__ == '__main__':
    try:
        result = observe(int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
    except BaseException as error:
        result = dict(outcome='listener_identity_incomplete', error_type=type(error).__name__,
                      reason=error.code if isinstance(error, IdentityIncomplete) else 'probe_error')
    print(json.dumps(result, allow_nan=False))
