"""Unit tests for the URL gate (NEO-505).

The plugin is a package with relative imports but its directory name is not importable, and
``__init__.py`` pulls in the Hermes CLI modules. We register a stub package pointing at the plugin
root and import only ``config``, ``mcp_client`` and ``hooks`` through it. Runs with the standard
library (``python3 -m unittest discover -s tests``) and under pytest alike.
"""

from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PKG = "agent_looker_hermes_under_test"
if PKG not in sys.modules:
    stub = types.ModuleType(PKG)
    stub.__path__ = [str(ROOT)]  # type: ignore[attr-defined]
    sys.modules[PKG] = stub

config = importlib.import_module(f"{PKG}.config")
mcp_client = importlib.import_module(f"{PKG}.mcp_client")
hooks = importlib.import_module(f"{PKG}.hooks")


def settings(**over):
    values = dict(config._DEFAULTS)
    values.update(over)
    return lambda key: values[key]


class CheckUrlSafetyNormalisation(unittest.TestCase):
    def call(self, payload, **kw):
        with mock.patch.object(mcp_client, "call_tool", return_value=payload) as call:
            result = mcp_client.check_url_safety("https://x.test/", **kw)
        return result, call

    def test_old_backend_shape_is_analyzed(self):
        result, call = self.call({"url": "u", "isSafe": False, "threats": ["MALWARE"]})
        self.assertEqual(result, {"status": "analyzed", "level": "unsafe", "unsafe": True, "threats": ["MALWARE"], "trust_score": None, "reasons": []})
        self.assertEqual(call.call_args.args, ("check_url_safety", {"url": "https://x.test/"}))

    def test_oldest_shape_flattens_threat_objects(self):
        result, _ = self.call({"isSafe": False, "threats": [{"threatType": "MALWARE"}, {"x": 1}]})
        self.assertEqual(result["threats"], ["MALWARE"])

    def test_new_backend_fields(self):
        result, _ = self.call({"isSafe": False, "status": "analyzed", "threats": ["PHISHING", "LOW_TRUST_SCORE"],
                               "trustScore": 1, "reasons": ["r1", "r2", "r3", "r4", "r5", "r6"]})
        self.assertEqual(result["status"], "analyzed")
        self.assertTrue(result["unsafe"])
        self.assertEqual(result["trust_score"], 1)
        self.assertEqual(result["reasons"], ["r1", "r2", "r3", "r4", "r5"])

    def test_not_analyzed_is_not_unsafe(self):
        result, _ = self.call({"isSafe": None, "status": "not_analyzed", "threats": [], "trustScore": None, "reasons": []})
        self.assertEqual(result["status"], "not_analyzed")
        self.assertIsNone(result["level"])
        self.assertFalse(result["unsafe"])
        self.assertEqual(result["threats"], [])

    def test_level_is_read_or_derived(self):
        result, _ = self.call({"isSafe": True, "level": "warning", "threats": ["MEDIUM_TRUST_SCORE"], "trustScore": 36})
        self.assertEqual(result["level"], "warning")
        self.assertFalse(result["unsafe"])
        self.assertEqual(result["threats"], ["MEDIUM_TRUST_SCORE"])
        result, _ = self.call({"isSafe": True, "level": "meh", "threats": []})
        self.assertEqual(result["level"], "safe")
        result, _ = self.call({"isSafe": False, "threats": ["MALWARE"]})
        self.assertEqual(result["level"], "unsafe")

    def test_no_data_is_safe(self):
        result, _ = self.call({"isSafe": True, "status": "no_data", "threats": []})
        self.assertEqual(result["status"], "no_data")
        self.assertFalse(result["unsafe"])

    def test_unknown_status_and_junk_fall_back(self):
        result, _ = self.call({"isSafe": False, "status": "weird", "threats": [], "trustScore": "1", "reasons": [3, None, "ok"]})
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["threats"], ["UNSAFE"])
        self.assertIsNone(result["trust_score"])
        self.assertEqual(result["reasons"], ["ok"])

    def test_deep_scan_adds_argument_and_passes_timeout(self):
        _, call = self.call({"isSafe": True}, deep_scan=True, timeout=35)
        self.assertEqual(call.call_args.args, ("check_url_safety", {"url": "https://x.test/", "deep_scan": True}))
        self.assertEqual(call.call_args.kwargs, {"timeout": 35})

    def test_payload_without_isSafe_raises(self):
        with mock.patch.object(mcp_client, "call_tool", return_value={"hello": 1}):
            with self.assertRaises(mcp_client.AgentLookerError):
                mcp_client.check_url_safety("https://x.test/")


ANALYZED_SAFE = {"status": "analyzed", "level": "safe", "unsafe": False, "threats": [], "trust_score": 92, "reasons": []}
ANALYZED_UNSAFE = {"status": "analyzed", "level": "unsafe", "unsafe": True, "threats": ["PHISHING", "LOW_TRUST_SCORE"], "trust_score": 1,
                   "reasons": ["This website has been reported for Phishing by IPQS", "second"]}
ANALYZED_WARNING = {"status": "analyzed", "level": "warning", "unsafe": False, "threats": ["MEDIUM_TRUST_SCORE"], "trust_score": 36,
                    "reasons": ["High number of suspicious websites on this IP-address"]}
NOT_ANALYZED = {"status": "not_analyzed", "level": None, "unsafe": False, "threats": [], "trust_score": None, "reasons": []}


class PreToolCall(unittest.TestCase):
    def setUp(self):
        self.token = mock.patch.object(config, "api_token", return_value="tok")
        self.token.start()
        self.addCleanup(self.token.stop)
        hooks._url_warnings.clear()

    def run_hook(self, verdicts, tool_name="browser_navigate", args=None, **over):
        """verdicts: sequence returned by successive check_url_safety calls."""
        with mock.patch.object(config, "setting", side_effect=settings(**over)), \
             mock.patch.object(mcp_client, "check_url_safety", side_effect=list(verdicts)) as check:
            result = hooks.pre_tool_call(tool_name, args if args is not None else {"url": "https://x.test/"})
        return result, check

    def test_warning_url_allows_and_is_remembered(self):
        result, check = self.run_hook([ANALYZED_WARNING])
        self.assertIsNone(result)
        self.assertEqual(check.call_count, 1)
        note = hooks._url_warnings["https://x.test/"]
        self.assertIn("[AGENT LOOKER URL SAFETY] https://x.test/ rated WARNING (trust score 36/100)", note)
        self.assertIn("do not enter credentials", note)
        self.assertIn("High number of suspicious websites on this IP-address", note)

    def test_warning_plus_unsafe_still_blocks(self):
        result, _ = self.run_hook([ANALYZED_WARNING, ANALYZED_UNSAFE], tool_name="web_extract",
                                  args={"urls": ["https://x.test/", "https://bad.test/"]})
        self.assertEqual(result["action"], "block")
        self.assertIn("https://bad.test/ [PHISHING, LOW_TRUST_SCORE]", result["message"])

    def test_safe_url_allows_with_one_call(self):
        result, check = self.run_hook([ANALYZED_SAFE])
        self.assertIsNone(result)
        self.assertEqual(check.call_count, 1)
        self.assertEqual(check.call_args.kwargs, {})

    def test_unsafe_url_blocks_with_threat_reason_and_score(self):
        result, _ = self.run_hook([ANALYZED_UNSAFE])
        self.assertEqual(result["action"], "block")
        self.assertIn("https://x.test/ [PHISHING, LOW_TRUST_SCORE]", result["message"])
        self.assertIn("This website has been reported for Phishing by IPQS", result["message"])
        self.assertIn("(trust score 1/100)", result["message"])
        self.assertNotIn("second", result["message"])

    def test_unknown_with_auto_deep_scan_on_rescans_with_long_timeout(self):
        result, check = self.run_hook([NOT_ANALYZED, ANALYZED_UNSAFE], timeout_seconds=10)
        self.assertEqual(result["action"], "block")
        self.assertEqual(check.call_count, 2)
        second = check.call_args_list[1]
        self.assertTrue(second.kwargs["deep_scan"])
        self.assertGreaterEqual(second.kwargs["timeout"], 35)

    def test_deep_scan_timeout_respects_a_larger_configured_timeout(self):
        _, check = self.run_hook([NOT_ANALYZED, ANALYZED_SAFE], timeout_seconds=60)
        self.assertEqual(check.call_args_list[1].kwargs["timeout"], 60)

    def test_unknown_then_safe_allows(self):
        result, check = self.run_hook([NOT_ANALYZED, ANALYZED_SAFE])
        self.assertIsNone(result)
        self.assertEqual(check.call_count, 2)

    def test_unknown_with_auto_deep_scan_off_blocks_with_guidance(self):
        result, check = self.run_hook([NOT_ANALYZED], url_auto_deep_scan=False)
        self.assertEqual(check.call_count, 1)
        self.assertEqual(result["action"], "block")
        self.assertIn("UNKNOWN", result["message"])
        self.assertIn("deep_scan=true", result["message"])
        self.assertIn("10-25 seconds", result["message"])

    def test_check_urls_off_skips_everything(self):
        result, check = self.run_hook([], check_urls=False)
        self.assertIsNone(result)
        self.assertEqual(check.call_count, 0)

    def test_transport_error_fails_open_unless_fail_closed(self):
        with mock.patch.object(config, "setting", side_effect=settings()), \
             mock.patch.object(mcp_client, "check_url_safety", side_effect=mcp_client.AgentLookerError("boom")):
            hooks._warned_error = False
            self.assertIsNone(hooks.pre_tool_call("browser_navigate", {"url": "https://x.test/"}))
        with mock.patch.object(config, "setting", side_effect=settings(fail_closed=True)), \
             mock.patch.object(mcp_client, "check_url_safety", side_effect=mcp_client.AgentLookerError("boom")):
            result = hooks.pre_tool_call("browser_navigate", {"url": "https://x.test/"})
            self.assertEqual(result["action"], "block")


class TransformToolResultUrlWarning(unittest.TestCase):
    """The WARNING note recorded by pre_tool_call is prepended once to the web_extract result."""

    ARGS = {"urls": ["https://x.test/"]}

    def setUp(self):
        hooks._url_warnings.clear()
        hooks._url_warnings["https://x.test/"] = "[AGENT LOOKER URL SAFETY] https://x.test/ rated WARNING"
        self.token = mock.patch.object(config, "api_token", return_value="tok")
        self.token.start()
        self.addCleanup(self.token.stop)

    def transform(self, text_verdict, **over):
        with mock.patch.object(config, "setting", side_effect=settings(**over)), \
             mock.patch.object(mcp_client, "check_text_safety", return_value=text_verdict):
            return hooks.transform_tool_result("web_extract", self.ARGS, "page body")

    def test_prepended_when_text_is_allowed_and_then_consumed(self):
        out = self.transform({"action": "ALLOW"})
        self.assertEqual(out, "[AGENT LOOKER URL SAFETY] https://x.test/ rated WARNING\n\npage body")
        self.assertNotIn("https://x.test/", hooks._url_warnings)
        self.assertIsNone(self.transform({"action": "ALLOW"}))  # second call: nothing left to add

    def test_prepended_above_the_content_warning_when_text_is_flagged(self):
        out = self.transform({"action": "FLAG", "categories": [{"name": "pii", "detected": True}]})
        self.assertTrue(out.startswith("[AGENT LOOKER URL SAFETY] https://x.test/ rated WARNING\n\n[AGENT LOOKER CONTENT SAFETY]"))
        self.assertTrue(out.endswith("\n\npage body"))

    def test_prepended_even_when_text_check_is_off(self):
        out = self.transform({"action": "ALLOW"}, check_text=False)
        self.assertEqual(out, "[AGENT LOOKER URL SAFETY] https://x.test/ rated WARNING\n\npage body")

    def test_other_urls_are_untouched(self):
        with mock.patch.object(config, "setting", side_effect=settings()), \
             mock.patch.object(mcp_client, "check_text_safety", return_value={"action": "ALLOW"}):
            out = hooks.transform_tool_result("web_extract", {"urls": ["https://other.test/"]}, "page body")
        self.assertIsNone(out)
        self.assertIn("https://x.test/", hooks._url_warnings)


if __name__ == "__main__":
    unittest.main()
