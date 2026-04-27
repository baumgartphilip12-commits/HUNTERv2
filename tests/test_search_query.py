"""Tests for the shared visible-search miniquery parser."""

from __future__ import annotations

import unittest

from hunter.search_query import matches_search_query, parse_search_query


class SearchQueryTests(unittest.TestCase):
    def test_plain_terms_all_must_match(self) -> None:
        document = {"text": ["Suspicious encoded PowerShell command"]}

        self.assertTrue(matches_search_query("powershell encoded", document))
        self.assertFalse(matches_search_query("powershell missing", document))

    def test_quoted_phrases_match_whole_strings(self) -> None:
        document = {"text": ["Suspicious encoded PowerShell command"]}

        self.assertTrue(matches_search_query('"encoded powershell"', document))
        self.assertFalse(matches_search_query('"powershell encoded"', document))

    def test_required_and_excluded_terms_are_supported(self) -> None:
        document = {"text": ["Suspicious encoded PowerShell command"]}

        self.assertTrue(matches_search_query('+powershell +"encoded powershell"', document))
        self.assertFalse(matches_search_query("powershell -encoded", document))

    def test_field_specific_terms_only_match_known_field_values(self) -> None:
        document = {
            "title": ["Domain IOC pivot"],
            "template": ["dns.question.name: <DOMAIN_IOC>"],
        }

        self.assertTrue(matches_search_query('title:"domain ioc"', document))
        self.assertFalse(matches_search_query('template:"domain ioc"', document))

    def test_unknown_fields_fall_back_to_literal_full_text_matching(self) -> None:
        self.assertTrue(matches_search_query("unknown:value", {"text": ["unknown:value"]}))
        self.assertFalse(matches_search_query("unknown:value", {"text": ["value"]}))

    def test_escaped_quotes_and_unmatched_quotes_degrade_safely(self) -> None:
        self.assertTrue(matches_search_query('"say \\"hello\\""', {"text": ['Operator should say "hello"']}))
        self.assertTrue(matches_search_query('"encoded command', {"text": ["encoded command"]}))
        self.assertEqual(parse_search_query('"encoded command').terms[0].value, "encoded command")


if __name__ == "__main__":
    unittest.main()
