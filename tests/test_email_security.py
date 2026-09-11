import unittest
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.exception
from tools.email_security_tool import email_security_check, _spf_policy, _discover_dynamic_selectors, _query_txt

class TestEmailSecurityScanner(unittest.TestCase):

    @patch('tools.email_security_tool.is_valid_domain')
    def test_invalid_domain_format(self, mock_is_valid):
        """Ensure invalid domains return a clean failure dictionary immediately."""
        mock_is_valid.return_value = False
        result = email_security_check("invalid_domain")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid domain format")

    def test_spf_policy_mapping(self):
        """Verify standard terminal mechanism string mapping logic and edge cases."""
        self.assertEqual(_spf_policy("v=spf1 include:_spf.google.com -all"), "fail")
        self.assertEqual(_spf_policy("v=spf1 include:spf.protection.outlook.com ~all"), "softfail")
        self.assertEqual(_spf_policy("v=spf1 ?all"), "neutral")
        self.assertEqual(_spf_policy("v=spf1 +all"), "pass")
        self.assertEqual(_spf_policy("v=spf1 all"), "pass")
        self.assertEqual(_spf_policy("v=spf1 redirect=example.com"), "missing")
        self.assertEqual(_spf_policy("v=spf1 include:_spf.example.com -allow"), "missing")
        self.assertEqual(_spf_policy("v=spf1 ip4:192.0.2.0/24"), "missing")
        self.assertEqual(_spf_policy("not an spf record"), "unknown")

    @patch('tools.email_security_tool._query_txt')
    @patch('tools.email_security_tool._discover_dynamic_selectors', return_value=[])
    @patch('tools.email_security_tool.is_valid_domain', return_value=True)
    def test_multiple_spf_records_detected(self, mock_valid, mock_discover, mock_query):
        """Verify that publishing multiple SPF records marks configuration as invalid."""
        def side_effect(name):
            if name == "multi-spf.com":
                return ["v=spf1 include:_spf.google.com -all", "v=spf1 include:mailgun.org ~all"], False
            return [], False
        mock_query.side_effect = side_effect

        result = email_security_check("multi-spf.com")
        self.assertTrue(result["success"])
        self.assertTrue(result["spf"]["found"])
        self.assertFalse(result["spf"]["valid"])
        self.assertEqual(len(result["spf"]["records"]), 2)
        self.assertIn(
            "Multiple SPF records found — SPF configuration is invalid. Consolidate the SPF mechanisms into a single SPF record.",
            result["recommendations"]
        )

    @patch('tools.email_security_tool._query_txt')
    @patch('tools.email_security_tool._discover_dynamic_selectors', return_value=[])
    @patch('tools.email_security_tool.is_valid_domain', return_value=True)
    def test_multiple_dmarc_records_detected(self, mock_valid, mock_discover, mock_query):
        """Verify that publishing multiple DMARC records marks configuration as invalid."""
        def side_effect(name):
            if name == "_dmarc.multi-dmarc.com":
                return ["v=DMARC1; p=reject", "v=DMARC1; p=quarantine"], False
            return [], False
        mock_query.side_effect = side_effect

        result = email_security_check("multi-dmarc.com")
        self.assertTrue(result["success"])
        self.assertTrue(result["dmarc"]["found"])
        self.assertFalse(result["dmarc"]["valid"])
        self.assertEqual(len(result["dmarc"]["records"]), 2)
        self.assertIn(
            "Multiple DMARC records found — DMARC configuration is ambiguous. Publish a single DMARC policy record.",
            result["recommendations"]
        )

    @patch('tools.email_security_tool._query_txt')
    @patch('tools.email_security_tool._discover_dynamic_selectors', return_value=[])
    @patch('tools.email_security_tool.is_valid_domain', return_value=True)
    def test_dkim_active_revoked_and_unrelated_records(self, mock_valid, mock_discover, mock_query):
        """Ensure tag-aware DKIM validator distinguishes active vs revoked vs unrelated TXT records."""
        def side_effect(name):
            if "default._domainkey." in name:
                return ["v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"], False  # Active key
            elif "selector1._domainkey." in name:
                return ["v=DKIM1; p="], False  # Revoked key per RFC
            elif "selector2._domainkey." in name:
                return ["some text with p=notadkimkey"], False  # Unrelated TXT
            elif "k1._domainkey." in name:
                return ["v=DKIM1"], False  # Malformed (missing p=)
            return [], False
        mock_query.side_effect = side_effect

        result = email_security_check("example.com")
        self.assertTrue(result["success"])
        self.assertTrue(result["dkim"]["found"])
        self.assertIn("default", result["dkim"]["found_selectors"])
        self.assertIn("selector1", result["dkim"]["revoked_selectors"])
        self.assertNotIn("selector2", result["dkim"]["found_selectors"])
        self.assertNotIn("selector2", result["dkim"]["revoked_selectors"])
        self.assertNotIn("k1", result["dkim"]["found_selectors"])

    @patch('tools.email_security_tool._query_txt')
    @patch('tools.email_security_tool._discover_dynamic_selectors', return_value=[])
    @patch('tools.email_security_tool.is_valid_domain', return_value=True)
    def test_empty_rua_tag_deduction(self, mock_valid, mock_discover, mock_query):
        """Ensure empty 'rua=' tag is treated as unconfigured reporting destination."""
        def side_effect(name):
            if name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject; rua="], False  # Empty rua=
            return [], False
        mock_query.side_effect = side_effect

        result = email_security_check("test.com")
        self.assertIn("DMARC has an empty rua= tag with no reporting address.", result["recommendations"])

    @patch('tools.email_security_tool._query_txt')
    @patch('tools.email_security_tool._discover_dynamic_selectors', return_value=[])
    @patch('tools.email_security_tool.is_valid_domain', return_value=True)
    def test_invalid_dmarc_policy_value(self, mock_valid, mock_discover, mock_query):
        """Ensure invalid DMARC p= value is marked as invalid."""
        def side_effect(name):
            if name == "_dmarc.test.com":
                return ["v=DMARC1; p=banana; rua=mailto:d@test.com"], False
            return [], False
        mock_query.side_effect = side_effect

        result = email_security_check("test.com")
        self.assertFalse(result["dmarc"]["valid"])
        self.assertEqual(result["dmarc"]["policy"], "invalid")
    @patch('dns.resolver.Resolver.resolve')
    def test_query_txt_fallback_mechanism(self, mock_resolve):
        """Ensure standard resolver timeouts trigger the public 1.1.1.1/8.8.8.8 fallback."""
        mock_resolve.side_effect = [
            dns.resolver.Timeout(),
            [MagicMock(strings=[b"fallback-record"])]
        ]
        records, failed = _query_txt("example.com")
        self.assertFalse(failed)
        self.assertIn("fallback-record", records)
        self.assertEqual(mock_resolve.call_count, 2)

    @patch('dns.resolver.Resolver.resolve')
    def test_discover_dynamic_selectors_google_mx(self, mock_resolve):
        """Verify that discovering a Google MX server appends relevant target selectors."""
        mock_mx = MagicMock()
        mock_mx.exchange = "aspmx.l.google.com."
        mock_resolve.return_value = [mock_mx]

        selectors = _discover_dynamic_selectors("example.com")
        self.assertIn("20161025", selectors)
        self.assertIn("20230601", selectors)

    @patch('tools.email_security_tool._query_txt')
    @patch('tools.email_security_tool._discover_dynamic_selectors')
    @patch('tools.email_security_tool.is_valid_domain', return_value=True)
    def test_perfect_score_scenario_openai(self, mock_valid, mock_discover, mock_query):
        """Verify an optimal setup scores 100% ('Excellent') with no recommendations."""
        mock_discover.return_value = []
        
        def side_effect_query(name):
            if name == "openai.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.openai.com":
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@openai.com"], False
            elif "default._domainkey.openai.com" in name:
                return ["v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQFAAOE"], False
            return [], False
        
        mock_query.side_effect = side_effect_query

        result = email_security_check("openai.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["security_score"], "100%")
        self.assertEqual(result["rating"], "Excellent")
        self.assertEqual(len(result["recommendations"]), 0)

    @patch('tools.email_security_tool._query_txt')
    @patch('tools.email_security_tool._discover_dynamic_selectors')
    @patch('tools.email_security_tool.is_valid_domain', return_value=True)
    def test_partial_score_scenario_github(self, mock_valid, mock_discover, mock_query):
        """Verify that softfail and quarantine settings pull down scores accurately."""
        mock_discover.return_value = []
        
        def side_effect_query(name):
            if name == "github.com":
                return ["v=spf1 ~all"], False
            elif name == "_dmarc.github.com":
                return ["v=DMARC1; p=quarantine; rua=mailto:dmarc@github.com"], False
            elif "default._domainkey.github.com" in name:
                return ["v=DKIM1; p=MIIB"], False
            return [], False
        
        mock_query.side_effect = side_effect_query

        result = email_security_check("github.com")
        self.assertEqual(result["security_score"], "80%")
        self.assertEqual(result["rating"], "Good")
        self.assertIn("SPF uses softfail (~all) — consider a hard fail (-all) for stronger protection", result["recommendations"])
        self.assertIn("DMARC policy is 'quarantine' — failing mail goes to spam.", result["recommendations"])

    @patch('tools.email_security_tool._query_txt')
    @patch('tools.email_security_tool._discover_dynamic_selectors')
    @patch('tools.email_security_tool.is_valid_domain', return_value=True)
    def test_missing_rua_tag_deduction(self, mock_valid, mock_discover, mock_query):
        """Ensure omitting the 'rua' visibility reporting tag deducts 5 points from DMARC."""
        mock_discover.return_value = []
        
        def side_effect_query(name):
            if name == "test.com":
                return ["v=spf1 -all"], False
            elif name == "_dmarc.test.com":
                return ["v=DMARC1; p=reject"], False  # Missing rua=
            return [], False
        
        mock_query.side_effect = side_effect_query

        result = email_security_check("test.com")
        self.assertEqual(result["security_score"], "60%")
        self.assertEqual(result["rating"], "Fair")


if __name__ == "__main__":
    unittest.main(verbosity=2)