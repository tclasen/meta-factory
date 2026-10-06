"""Bounded private streaming checks for known APP-007/AC-018 secret canaries.

Inputs stay operator-side. Receipts contain no raw chunks, values or matched
representations. Log/source coverage and transport identity are separate trusted
preconditions; this helper does not retrieve logs or establish their completeness.
"""
import base64
import html
import json
from urllib.parse import quote, quote_plus


DEFAULT_BYTES = 8 * 1024 * 1024


def canary_patterns(values):
    """Private literal and selected common reversible text encodings only."""
    if (not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 32
            or any(not isinstance(value, str) or '\x00' in value
                   or not 8 <= len(value.encode()) <= 4096 for value in values)):
        raise ValueError('Bounded nonempty known canaries required')
    patterns = set()
    for value in values:
        raw = value.encode()
        patterns.add(raw)
        for text in (json.dumps(value, ensure_ascii=True)[1:-1],
                     json.dumps(value, ensure_ascii=False)[1:-1],
                     quote(value, safe=''), quote_plus(value, safe=''), html.escape(value),
                     raw.hex(), raw.hex().upper()):
            patterns.add(text.encode())
        for encoded in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
            patterns.add(encoded); patterns.add(encoded.rstrip(b'='))
    return tuple(sorted(patterns, key=len, reverse=True))


def binary_canary_patterns(values):
    """Private exact binary values and base64/hex forms, with fixed memory bounds.

    Raw compressed archives are compared as bytes rather than decoded as UTF-8.
    No arbitrary enclosing encodings, fragments or reconstructed archives claimed.
    """
    if (not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 4
            or any(not isinstance(value, bytes) or not 8 <= len(value) <= 65536
                   for value in values)
            or sum(map(len, values)) > 131072):
        raise ValueError('Bounded nonempty known binary canaries required')
    patterns = set()
    for raw in values:
        patterns.add(raw)
        patterns.add(raw.hex().encode())
        patterns.add(raw.hex().upper().encode())
        for encoded in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
            patterns.add(encoded)
            patterns.add(encoded.rstrip(b'='))
    return tuple(sorted(patterns, key=len, reverse=True))


def scan_secret_chunks(chunks, values=None, *, binary_values=None, max_bytes=DEFAULT_BYTES, max_chunks=65536):
    """Inspect one independently bound stream; require complete EOF for absence.

    Optional binary_values selects exact known bytes (including NUL/non-UTF-8)
    and their base64/hex forms. Text and binary values may be combined.
    Split needles are matched across adjacent chunks of this stream, including
    encoded forms. Never concatenate unrelated sources. A detected canary remains
    evidence even if the stream later fails or exceeds a bound. Absence with
    complete=False cannot pass an acceptance check. Caller owns source cleanup.
    Arbitrary encodings, encryption, fragments and whole-container history are
    outside this scanner's guarantee.
    """
    if type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024 * 1024:
        raise ValueError('Invalid secret scan byte bound')
    if type(max_chunks) is not int or not 1 <= max_chunks <= 65536:
        raise ValueError('Invalid secret scan chunk bound')
    if values is None and binary_values is None:
        raise ValueError('Known text or binary canaries required')
    patterns = (canary_patterns(values) if values is not None else ())
    if binary_values is not None:
        patterns += binary_canary_patterns(binary_values)
    overlap = max(map(len, patterns)) - 1
    receipt = dict(canary_present=False, complete=False, bytes_inspected=0, outcome='incomplete')
    tail = b''; count = 0
    try:
        for chunk in chunks:
            count += 1
            if count > max_chunks:
                receipt['outcome'] = 'chunk_limit'
                return receipt
            if not isinstance(chunk, bytes):
                receipt['outcome'] = 'invalid_chunk'
                return receipt
            remaining = max_bytes - receipt['bytes_inspected']
            selected = chunk[:remaining]
            data = tail + selected
            if not receipt['canary_present']:
                receipt['canary_present'] = any(pattern in data for pattern in patterns)
            receipt['bytes_inspected'] += len(selected)
            tail = data[-overlap:] if overlap else b''
            if len(chunk) > remaining:
                receipt['outcome'] = 'byte_limit'
                return receipt
    except Exception:
        # Exception text or repr may contain secrets; do not retain it.
        receipt['outcome'] = 'source_error'
        return receipt
    receipt.update(complete=True, outcome='eof')
    return receipt
