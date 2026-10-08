"""Bounded Linux network-namespace checks for network-none browser workers.

Dormant interfaces are permitted only while down, unaddressed and unrouted.
The parent still independently verifies Docker network=none and dropped caps.
"""
import errno
import ipaddress
from pathlib import Path
import re
import socket
import struct
import sys


MAX_BYTES = 65536


def bounded_text(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise RuntimeError('Browser network observation exceeds bound')
    return data.decode('ascii')


def collect_network():
    if sys.platform != 'linux':
        raise RuntimeError('Linux browser network observation required')
    import fcntl
    before = socket.if_nameindex()
    if not 1 <= len(before) <= 64:
        raise RuntimeError('Browser interface count unavailable')
    interfaces = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        for index, name in before:
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name):
                raise RuntimeError('Browser interface identity unavailable')
            request = struct.pack('256s', name.encode('ascii'))
            flags = struct.unpack_from('H', fcntl.ioctl(channel.fileno(), 0x8913, request), 16)[0]
            try:
                address = socket.inet_ntoa(fcntl.ioctl(channel.fileno(), 0x8915, request)[20:24])
            except OSError as error:
                if error.errno != errno.EADDRNOTAVAIL:
                    raise
                address = None
            interfaces.append(dict(index=index, name=name, flags=flags, ipv4_address=address))
    value = dict(interfaces=interfaces, ipv4_routes=bounded_text('/proc/net/route'),
                 ipv6_addresses=bounded_text('/proc/net/if_inet6'),
                 ipv6_routes=bounded_text('/proc/net/ipv6_route'))
    if before != socket.if_nameindex():
        raise RuntimeError('Browser interface identities changed')
    return value


def validate_network(value):
    """Return a configuration fingerprint; never emit raw network observations."""
    if not isinstance(value, dict) or set(value) != {
            'interfaces', 'ipv4_routes', 'ipv6_addresses', 'ipv6_routes'}:
        raise RuntimeError('Complete browser network observation required')
    interfaces = value['interfaces']
    if not isinstance(interfaces, list) or not 1 <= len(interfaces) <= 64:
        raise RuntimeError('Browser interface count unavailable')
    names, indices, records = set(), set(), []
    for item in interfaces:
        if (not isinstance(item, dict) or set(item) != {'index', 'name', 'flags', 'ipv4_address'}
                or type(item['index']) is not int or item['index'] <= 0 or item['index'] in indices
                or not isinstance(item['name'], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', item['name'])
                or item['name'] in names or type(item['flags']) is not int or not 0 <= item['flags'] <= 65535):
            raise RuntimeError('Browser interface identity unavailable')
        if item['ipv4_address'] is not None and not isinstance(item['ipv4_address'], str):
            raise RuntimeError('Browser interface address unavailable')
        names.add(item['name']); indices.add(item['index'])
        if item['name'] == 'lo':
            if not item['flags'] & 8:
                raise RuntimeError('Browser loopback flags unavailable')
            if item['ipv4_address'] is not None and not ipaddress.IPv4Address(item['ipv4_address']).is_loopback:
                raise RuntimeError('Browser loopback address differs')
        elif item['flags'] & (1 | 64) or item['ipv4_address'] is not None:
            raise RuntimeError('Browser has active or addressed nonloopback interface')
        records.append((item['index'], item['name'], item['flags'], item['ipv4_address']))
    if 'lo' not in names:
        raise RuntimeError('Browser loopback interface unavailable')
    loopback_index = next(item['index'] for item in interfaces if item['name'] == 'lo')
    tables = {}
    for key in ('ipv4_routes', 'ipv6_addresses', 'ipv6_routes'):
        text = value[key]
        if not isinstance(text, str) or len(text.encode()) > MAX_BYTES or len(text.splitlines()) > 256:
            raise RuntimeError('Browser route observation exceeds bound')
        tables[key] = [line.split() for line in text.splitlines() if line.strip()]
    routes = tables['ipv4_routes']
    if not routes or routes[0] != 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT'.split():
        raise RuntimeError('Browser IPv4 route header unavailable')
    configurations = []
    for row in routes[1:]:
        if len(row) != 11 or row[0] != 'lo':
            raise RuntimeError('Browser has nonloopback or malformed IPv4 route')
        for index in (1, 2, 3, 7):
            if not re.fullmatch(r'[0-9A-Fa-f]{1,8}', row[index]):
                raise RuntimeError('Browser IPv4 route unavailable')
        for index in (4, 5, 6, 8, 9, 10):
            if not re.fullmatch(r'[0-9]{1,10}', row[index]):
                raise RuntimeError('Browser IPv4 route unavailable')
        configurations.append(tuple(row[:4] + row[6:]))
    addresses = []
    for row in tables['ipv6_addresses']:
        if (len(row) != 6 or row[5] != 'lo' or not re.fullmatch(r'[0-9A-Fa-f]{32}', row[0])
                or any(not re.fullmatch(r'[0-9A-Fa-f]{1,8}', field) for field in row[1:5])
                or int(row[1], 16) != loopback_index or int(row[2], 16) > 128
                or not ipaddress.IPv6Address(int(row[0], 16)).is_loopback):
            raise RuntimeError('Browser has nonloopback or malformed IPv6 address')
        addresses.append(tuple(row))
    ipv6_routes = []
    for row in tables['ipv6_routes']:
        if (len(row) != 10 or row[9] != 'lo'
                or any(not re.fullmatch(r'[0-9A-Fa-f]{32}', row[i]) for i in (0, 2, 4))
                or any(not re.fullmatch(r'[0-9A-Fa-f]{1,8}', row[i]) for i in (1, 3, 5, 6, 7, 8))
                or int(row[1], 16) > 128 or int(row[3], 16) > 128):
            raise RuntimeError('Browser has nonloopback or malformed IPv6 route')
        ipv6_routes.append(tuple(row[:6] + row[8:]))
    return (tuple(sorted(records)), tuple(sorted(configurations)),
            tuple(sorted(addresses)), tuple(sorted(ipv6_routes)))


def verify_loopback_network():
    first = validate_network(collect_network())
    second = validate_network(collect_network())
    if first != second:
        raise RuntimeError('Browser network configuration changed')
