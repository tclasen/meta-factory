"""Decode bounded private CRI log bytes; file EOF is not log-history evidence."""
from datetime import datetime
import re

from .secret_scan import DEFAULT_BYTES


MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 65536
MAX_CHUNKS = 65536
_TIME = re.compile(rb'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})')


def decode_cri_log(chunks, *, max_bytes=DEFAULT_BYTES):
    """Return private stdout/stderr bytes from a complete bounded CRI file.

    F records end payload lines; P records continue them without a newline.
    Interleaved streams remain separate. Never decode payloads as text or attach
    timestamps to them. Refuse malformed headers, unfinished fragments, partial
    final frames, reader failures and bounds. All exception messages are fixed.

    Caller independently binds the node/file to namespace, Pod UID and container
    identity, verifies EOF and cleanup, and handles rotation/history continuity.
    An EOF here proves only parsing of supplied bytes. Files must stay private;
    do not persist the returned raw streams in operator evidence or builder mounts.
    """
    if type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024 * 1024:
        raise ValueError('Private CRI byte bound required')
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    partial = dict.fromkeys(streams, False)
    buffer = bytearray()
    total, count, chunk_count = 0, 0, 0
    try:
        for chunk in chunks:
            chunk_count += 1
            if chunk_count > MAX_CHUNKS or not isinstance(chunk, bytes):
                raise ValueError('Private CRI chunk bound')
            total += len(chunk)
            if total > max_bytes: raise ValueError('Private CRI byte bound')
            buffer.extend(chunk)
            consumed = 0
            while True:
                end = buffer.find(b'\n', consumed)
                if end < 0: break
                if end - consumed > MAX_LINE_BYTES or count >= MAX_RECORDS:
                    raise ValueError('Private CRI record bound')
                line = bytes(buffer[consumed:end])
                consumed = end + 1
                fields = line.split(b' ', 3)
                if (len(fields) != 4 or not _TIME.fullmatch(fields[0])
                        or fields[1] not in (b'stdout', b'stderr')
                        or fields[2] not in (b'P', b'F')):
                    raise ValueError('Private CRI framing unavailable')
                # Validate calendar/clock fields as well as the wire grammar.
                if fields[0][-1:] != b'Z' and (int(fields[0][-5:-3]) > 23 or int(fields[0][-2:]) > 59):
                    raise ValueError('Private CRI timestamp unavailable')
                datetime.fromisoformat(fields[0].decode('ascii').replace('Z', '+00:00'))
                stream = fields[1].decode('ascii')
                streams[stream].extend(fields[3])
                partial[stream] = fields[2] == b'P'
                if not partial[stream]: streams[stream].extend(b'\n')
                count += 1
            del buffer[:consumed]
            if len(buffer) > MAX_LINE_BYTES:
                raise ValueError('Private CRI record bound')
        if buffer or any(partial.values()):
            raise ValueError('Private CRI incomplete frame')
    except Exception:
        raise ValueError('Complete private CRI framing unavailable') from None
    return dict(stdout=bytes(streams['stdout']), stderr=bytes(streams['stderr']),
                records=count, input_bytes=total)
