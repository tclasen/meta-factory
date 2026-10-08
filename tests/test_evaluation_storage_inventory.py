"""Whole-bucket pagination controls; private identities never become acceptance."""
import unittest
from unittest.mock import patch
from urllib.parse import quote
from xml.sax.saxutils import escape

from evaluation.storage_inventory import InventoryIncomplete, enumerate_inventory, summarize_inventory


def page(kind, entries=(), *, size=2, marker=None, next_marker=None, bucket='fixture-bucket'):
    root = 'ListBucketResult' if kind == 'current' else 'ListVersionsResult'
    fields = dict(Name=bucket, Prefix='', MaxKeys=str(size), IsTruncated=str(next_marker is not None).lower(),
                  EncodingType='url')
    if kind == 'current':
        fields['KeyCount'] = str(len(entries))
        if marker is not None:fields['ContinuationToken'] = marker
        if next_marker is not None:fields['NextContinuationToken'] = next_marker
    else:
        fields['KeyMarker'] = quote(marker[0], safe='') if marker else ''
        fields['VersionIdMarker'] = marker[1] if marker else ''
        if next_marker:
            fields['NextKeyMarker'] = quote(next_marker[0], safe='')
            fields['NextVersionIdMarker'] = next_marker[1]
    text = '<' + root + ' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    text += ''.join('<' + key + '>' + escape(value) + '</' + key + '>' for key, value in fields.items())
    for key, version, latest, deleted in entries:
        tag = 'Contents' if kind == 'current' else ('DeleteMarker' if deleted else 'Version')
        text += '<' + tag + '><Key>' + escape(quote(key, safe='')) + '</Key>'
        if kind == 'history':
            text += '<VersionId>' + escape(version) + '</VersionId><IsLatest>' + str(latest).lower() + '</IsLatest>'
        text += '</' + tag + '>'
    return (text + '</' + root + '>').encode()


class StorageInventoryTest(unittest.TestCase):
    def enumerate(self, kind, responses, **kwargs):
        calls = []
        def fetch(actual_kind, marker, size):
            calls.append((actual_kind, marker, size))
            return responses[len(calls)-1]
        value = enumerate_inventory(fetch, bucket='fixture-bucket', kind=kind, page_size=2, **kwargs)
        return value, calls

    def test_current_pagination_preserves_encoded_keys_without_plus_conversion(self):
        keys = ['a+% ü', 'nested/private-key']
        responses = [(200, page('current', [(keys[0], None, True, False)], next_marker='opaque+/=')),
                     (200, page('current', [(keys[1], None, True, False)], marker='opaque+/='))]
        result, calls = self.enumerate('current', responses)
        self.assertTrue(result['complete'])
        self.assertEqual([item['key'] for item in result['items']], keys)
        self.assertEqual(calls, [('current', None, 2), ('current', 'opaque+/=', 2)])
        self.assertEqual(len(result['sha256']), 64)
        self.assertNotIn('private', result)

    def test_history_retains_old_versions_and_delete_markers_across_pages(self):
        marker = ('a+% ü', 'opaque+/=')
        entries = [('a+% ü', 'opaque+/=', True, True), ('a+% ü', 'older', False, False),
                   ('b', 'null', True, False)]
        result, calls = self.enumerate('history', [(200, page('history', entries[:1], next_marker=marker)),
                                                  (200, page('history', entries[1:], marker=marker))])
        self.assertEqual(len(result['items']), 3)
        self.assertEqual(sum(item['delete_marker'] for item in result['items']), 1)
        self.assertEqual(calls[-1], ('history', marker, 2))
        self.assertTrue(result['complete'])

    def test_empty_terminal_listing_is_valid_for_both_views(self):
        for kind in ('current', 'history'):
            result, _ = self.enumerate(kind, [(200, page(kind))])
            self.assertEqual(result['items'], [])
            self.assertTrue(result['complete'])

    def test_filtered_unknown_duplicate_and_mismatched_page_scopes_are_refused(self):
        source = page('current', [('key', None, True, False)])
        for raw in (source.replace(b'<Prefix></Prefix>', b'<Prefix>subset/</Prefix>'),
                    source.replace(b'<Prefix>', b'<Delimiter>/</Delimiter><Prefix>'),
                    source.replace(b'<Prefix>', b'<CommonPrefixes/><Prefix>'),
                    source.replace(b'fixture-bucket', b'other-bucket'),
                    source.replace(b'<KeyCount>1', b'<KeyCount>2'),
                    source.replace(b'<EncodingType>url', b'<EncodingType>unknown'),
                    source.replace(b'<MaxKeys>2', b'<MaxKeys>1000'),
                    source.replace(b'<Prefix>', b'<Prefix/><Prefix>'),
                    source.replace(b'<Key>', b'<Key xmlns="foreign">'),
                    source.replace(b'<Contents>', b'<Contents><Owner><Version/></Owner>')):
            with self.subTest(raw=raw), self.assertRaises(InventoryIncomplete):
                self.enumerate('current', [(200, raw)])

    def test_truncation_missing_repeated_and_wrong_echo_markers_are_refused(self):
        first = page('current', [('a', None, True, False)], next_marker='next')
        for responses in (
                [(200, first.replace(b'<NextContinuationToken>next</NextContinuationToken>', b''))],
                [(200, first), (200, page('current', [('b', None, True, False)], marker='wrong'))],
                [(200, first), (200, page('current', [('b', None, True, False)], marker='next', next_marker='next'))],
                [(200, page('current', next_marker='next'))],
                [(200, first.replace(b'<IsTruncated>true', b'<IsTruncated>false'))]):
            with self.subTest(responses=responses), self.assertRaises(InventoryIncomplete):
                self.enumerate('current', responses)
        historical = page('history', [('a', 'v', True, False)], next_marker=('a', 'v'))
        for raw in (historical.replace(b'<NextVersionIdMarker>v</NextVersionIdMarker>', b''),
                    historical.replace(b'<KeyMarker></KeyMarker>', b'<KeyMarker>wrong</KeyMarker>')):
            with self.assertRaises(InventoryIncomplete):self.enumerate('history', [(200, raw)])

    def test_duplicate_versions_and_ambiguous_latest_flags_are_refused(self):
        for entries in ([('a', 'v', True, False), ('a', 'v', False, True)],
                        [('a', 'v', False, False)],
                        [('a', 'v', True, False), ('a', 'older', True, False)]):
            with self.assertRaises(InventoryIncomplete):
                self.enumerate('history', [(200, page('history', entries))])
        for keys in (['a', 'a'], ['b', 'a']):
            with self.assertRaises(InventoryIncomplete):
                self.enumerate('current', [(200, page('current', [(key, None, True, False) for key in keys]))])

    def test_bounds_unavailable_xml_and_invalid_url_encoding_never_complete(self):
        source = page('current', [('a', None, True, False)])
        for status, raw in ((403, source), (404, source), (200, b'x' * (1024*1024 + 1)),
                            (200, b'\xff'), (200, source.decode().encode('utf-16')),
                            (200, b'<!DOCTYPE ListBucketResult>' + source),
                            (200, source.replace(b'<Key>a', b'<Key>%GG')),
                            (200, source.replace(b'<Key>a', b'<Key>%FF')),
                            (200, source.replace(b'<Key>a', b'<Key>%00'))):
            with self.assertRaises(InventoryIncomplete):self.enumerate('current', [(status, raw)])
        first = page('current', [('a', None, True, False)], next_marker='next')
        with self.assertRaises(InventoryIncomplete):self.enumerate('current', [(200, first)], max_pages=1)
        with self.assertRaises(InventoryIncomplete):
            self.enumerate('current', [(200, page('current', [('a', None, True, False), ('b', None, True, False)]))], max_entries=1)

    def test_history_digest_is_independent_of_xml_group_order(self):
        entries = [('b', 'v', True, False), ('a', 'v', True, True)]
        first, _ = self.enumerate('history', [(200, page('history', entries))])
        second, _ = self.enumerate('history', [(200, page('history', entries[::-1]))])
        self.assertEqual(first['sha256'], second['sha256'])

    def test_current_history_composition_counts_retained_deleted_scopes(self):
        current, _ = self.enumerate('current', [(200, page('current', [('a', None, True, False)]))])
        marker = ('a', 'older')
        history, _ = self.enumerate('history', [
            (200, page('history', [('a', 'latest', True, False), ('a', 'older', False, False)], next_marker=marker)),
            (200, page('history', [('b', 'deleted', True, True)], marker=marker))])
        summary = summarize_inventory(current, history)
        self.assertEqual(summary['current_object_count'], 1)
        self.assertEqual(summary['retained_version_count'], 2)
        self.assertEqual(summary['delete_marker_count'], 1)
        self.assertTrue(summary['listing_complete'])
        self.assertIsNone(summary['privacy_verified'])
        self.assertFalse(summary['atomic_snapshot_verified'])
        self.assertNotIn('items', summary)
        self.assertNotIn('older', str(summary))

    def test_disagreeing_views_and_partial_views_never_get_complete_summary(self):
        current, _ = self.enumerate('current', [(200, page('current', [('a', None, True, False)]))])
        history, _ = self.enumerate('history', [(200, page('history', [('a', 'deleted', True, True)]))])
        with self.assertRaises(InventoryIncomplete):summarize_inventory(current, history)
        with self.assertRaises(InventoryIncomplete):summarize_inventory(dict(current, complete=False), history)

    def test_deadline_overrun_never_returns_a_terminal_page_as_complete(self):
        source = page('current')
        with patch('evaluation.storage_inventory.time.monotonic', side_effect=[0, 0, 31]):
            with self.assertRaises(InventoryIncomplete):self.enumerate('current', [(200, source)], timeout=30)
        with patch('evaluation.storage_inventory.time.time', side_effect=[0, 0, 31]):
            with self.assertRaises(InventoryIncomplete):self.enumerate('current', [(200, source)], timeout=30)

    def test_history_cursor_can_identify_a_version_not_returned_on_its_page(self):
        marker = ('a', 'older')
        result, calls = self.enumerate('history', [
            (200, page('history', [('a', 'latest', True, False)], next_marker=marker)),
            (200, page('history', [('a', 'older', False, False)], marker=marker))])
        self.assertEqual(len(result['items']), 2)
        self.assertEqual(calls[-1][1], marker)


if __name__ == '__main__':
    unittest.main()
