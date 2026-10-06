"""CRI framing must preserve binary payloads and refuse incomplete absence."""
import unittest
from unittest.mock import patch

from evaluation.cri_log import decode_cri_log
from evaluation.secret_scan import scan_secret_chunks


TIME = b'2026-10-05T12:30:45.123456789Z'


def frame(payload, stream=b'stdout', tag=b'F', timestamp=TIME):
    return b' '.join((timestamp, stream, tag, payload)) + b'\n'


class CRILogTest(unittest.TestCase):
    def test_interleaved_partial_binary_records_across_every_chunk_boundary(self):
        raw = frame(b'private\x00\xff', tag=b'P') + frame(b'other', b'stderr') + frame(b' binary with spaces') + frame(b'next')
        for split in range(len(raw) + 1):
            result = decode_cri_log([raw[:split], raw[split:]])
            self.assertEqual(result['stdout'], b'private\x00\xff binary with spaces\nnext\n')
            self.assertEqual(result['stderr'], b'other\n')
            self.assertEqual((result['records'], result['input_bytes']), (4, len(raw)))
        self.assertEqual(decode_cri_log([bytes([v]) for v in raw]), result)

    def test_line_endings_empty_payloads_and_carriage_returns_are_preserved(self):
        raw = frame(b'') + frame(b'\r') + frame(b'') + frame(b'fragment', tag=b'P') + frame(b'')
        self.assertEqual(decode_cri_log([raw])['stdout'], b'\n\r\n\nfragment\n')
        self.assertEqual(decode_cri_log([]), dict(stdout=b'', stderr=b'', records=0, input_bytes=0))

    def test_newline_bearing_binary_canary_detected_without_timestamp_insertion(self):
        needle = b'PK\x03\x04\x00\xff\nprivate-archive\nend'
        raw = b''.join(frame(line) for line in needle.split(b'\n'))
        result = decode_cri_log([raw])
        self.assertTrue(scan_secret_chunks([result['stdout']], binary_values=[needle])['canary_present'])
        separate = decode_cri_log([frame(b'private-', b'stdout'), frame(b'archive', b'stderr')])
        for stream in ('stdout', 'stderr'):
            self.assertFalse(scan_secret_chunks([separate[stream]], ["private-archive"])['canary_present'])

    def test_bad_headers_timestamps_and_unfinished_streams_are_sanitized(self):
        secret = b'Private-malformed-log-secret'
        for raw in (secret+b'\n', frame(secret, b'unknown'), frame(secret, tag=b'X'),
                    frame(secret, timestamp=b'2026-02-30T12:30:45Z'),
                    frame(secret, timestamp=b'2026-10-05T25:30:45Z'),
                    frame(secret, timestamp=b'2026-10-05T12:30:45'),
                    frame(secret, timestamp=b'2026-10-05T12:30:45+01:99'),
                    frame(secret)[:-1], frame(secret, tag=b'P'),
                    frame(secret, tag=b'P')+frame(b'complete', b'stderr')):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, '^Complete private CRI framing unavailable$'):
                decode_cri_log([raw])

    def test_supported_fraction_lengths_and_timezone_offsets(self):
        for timestamp in (b'2026-10-05T12:30:45Z', b'2026-10-05T12:30:45.1+01:30',
                          b'2026-10-05T12:30:45.123456789-05:00'):
            self.assertEqual(decode_cri_log([frame(b'ordinary', timestamp=timestamp)])['stdout'], b'ordinary\n')

    def test_reader_failure_and_explicit_bounds_refuse_partial_result(self):
        def failing():
            yield frame(b'ordinary')
            raise RuntimeError('private reader diagnostic')
        for chunks in (failing(), [None], [bytearray(b'private')]):
            with self.assertRaisesRegex(ValueError, '^Complete private CRI framing unavailable$'):
                decode_cri_log(chunks)
        raw = frame(b'ordinary')
        self.assertEqual(decode_cri_log([raw], max_bytes=len(raw))['records'], 1)
        with self.assertRaises(ValueError): decode_cri_log([raw], max_bytes=len(raw)-1)
        for bound in (True, 0, 64*1024*1024+1, float('inf')):
            with self.assertRaises(ValueError): decode_cri_log([], max_bytes=bound)
        for name, chunks in (('MAX_RECORDS', [raw+raw]), ('MAX_CHUNKS', [b'', b'']), ('MAX_LINE_BYTES', [raw])):
            with patch('evaluation.cri_log.'+name, 1), self.assertRaises(ValueError):
                decode_cri_log(chunks)


if __name__ == '__main__': unittest.main()
