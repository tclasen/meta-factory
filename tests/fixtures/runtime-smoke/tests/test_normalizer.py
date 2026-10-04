import unittest

from normalizer import normalize_tag


class NormalizeTagTest(unittest.TestCase):
    def test_surrounding_whitespace(self):
        self.assertEqual(normalize_tag(" \t Incident \n"), "incident")

    def test_lowercase(self):
        self.assertEqual(normalize_tag("INCIDENT"), "incident")

    def test_empty_input(self):
        self.assertEqual(normalize_tag(""), "")

    def test_internal_spaces(self):
        self.assertEqual(normalize_tag("Incident  Report"), "incident  report")


if __name__ == "__main__":
    unittest.main()
