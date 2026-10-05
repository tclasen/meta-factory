"""Known-canary detection does not convert truncation or source failures into pass."""
import base64
import json
import unittest
from urllib.parse import quote

from evaluation.secret_scan import scan_secret_chunks


CANARY = 'Private-fixture-token-2026!'


class SecretScanTest(unittest.TestCase):
    def test_split_literal_and_encoded_forms(self):
        unicode = 'Synthetic-雪-"\\\n-token'
        values = [CANARY, unicode]
        forms = [CANARY.encode(), unicode.encode(), quote(unicode, safe='').encode(),
                 json.dumps(unicode, ensure_ascii=True)[1:-1].encode(),
                 base64.b64encode(unicode.encode()), base64.urlsafe_b64encode(unicode.encode()).rstrip(b'='),
                 unicode.encode().hex().encode(), unicode.encode().hex().upper().encode()]
        for form in forms:
            for split in range(1, len(form)):
                with self.subTest(length=len(form), split=split):
                    receipt = scan_secret_chunks([b'prefix ' + form[:split], form[split:] + b' suffix'], values)
                    self.assertTrue(receipt['canary_present'])
                    self.assertTrue(receipt['complete'])
                    self.assertEqual(set(receipt), {'canary_present', 'complete', 'bytes_inspected', 'outcome'})
                    self.assertNotIn(CANARY, repr(receipt))

    def test_clean_stream_and_empty_stream_reach_eof(self):
        for chunks in ([], [b'ordinary log\n', b'healthy fixture\n'], [b'', b'']):
            receipt = scan_secret_chunks(chunks, [CANARY])
            self.assertFalse(receipt['canary_present'])
            self.assertTrue(receipt['complete'])
            self.assertEqual(receipt['outcome'], 'eof')

    def test_byte_limit_is_incomplete_even_when_inspected_prefix_is_clean(self):
        receipt = scan_secret_chunks([b'clean', CANARY.encode()], [CANARY], max_bytes=5)
        self.assertEqual(receipt, dict(canary_present=False, complete=False, bytes_inspected=5, outcome='byte_limit'))
        receipt = scan_secret_chunks([CANARY.encode() + b' beyond'], [CANARY], max_bytes=len(CANARY))
        self.assertTrue(receipt['canary_present'])
        self.assertFalse(receipt['complete'])

    def test_exact_limit_needs_eof_not_a_full_buffer(self):
        self.assertTrue(scan_secret_chunks([b'clean'], [CANARY], max_bytes=5)['complete'])
        self.assertFalse(scan_secret_chunks([b'clean', b'x'], [CANARY], max_bytes=5)['complete'])

    def test_chunk_limit_bounds_empty_and_tiny_streams(self):
        def unlimited():
            while True:yield b''
        receipt = scan_secret_chunks(unlimited(), [CANARY], max_chunks=3)
        self.assertEqual(receipt['outcome'], 'chunk_limit')
        self.assertFalse(receipt['complete'])

    def test_prior_detection_survives_private_source_error(self):
        def broken():
            yield CANARY.encode()
            raise RuntimeError('diagnostic contains ' + CANARY)
        receipt = scan_secret_chunks(broken(), [CANARY])
        self.assertTrue(receipt['canary_present'])
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['outcome'], 'source_error')
        self.assertNotIn(CANARY, repr(receipt))

    def test_missing_or_invalid_stream_cannot_establish_absence(self):
        for chunks in (None, [b'ordinary', 'not bytes'], [bytearray(b'ordinary')]):
            receipt = scan_secret_chunks(chunks, [CANARY])
            self.assertFalse(receipt['complete'])
            self.assertIn(receipt['outcome'], ('source_error', 'invalid_chunk'))

    def test_unrelated_sources_are_not_joined(self):
        raw = CANARY.encode();split = len(raw) // 2
        for chunks in ([raw[:split]], [raw[split:]]):
            receipt = scan_secret_chunks(chunks, [CANARY])
            self.assertTrue(receipt['complete'])
            self.assertFalse(receipt['canary_present'])

    def test_invalid_canaries_and_bounds_refused(self):
        for values in ([], [None], ['short'], ['x' * 4097], ['token\x00bad'], CANARY):
            with self.assertRaises(ValueError):scan_secret_chunks([], values)
        for kwargs in ({'max_bytes':True}, {'max_bytes':0}, {'max_bytes':64*1024*1024+1},
                       {'max_chunks':True}, {'max_chunks':0}, {'max_chunks':65537}):
            with self.assertRaises(ValueError):scan_secret_chunks([], [CANARY], **kwargs)

    def test_a_detection_remains_visible_at_later_chunk_limit(self):
        receipt = scan_secret_chunks([CANARY.encode(), b''], [CANARY], max_chunks=1)
        self.assertTrue(receipt['canary_present'])
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['outcome'], 'chunk_limit')


if __name__ == '__main__':unittest.main()
