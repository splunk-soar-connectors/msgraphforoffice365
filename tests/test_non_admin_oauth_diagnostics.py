# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import ast
import hashlib
import re
import secrets
import unittest
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "office365_connector.py"
DIAGNOSTIC_STATE_KEY = "non_admin_auth_diagnostic"


def _load_diagnostic_policy():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    connector = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Office365Connector")
    methods = [
        node
        for node in connector.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_get_non_admin_state_revision_fingerprint", "_record_non_admin_oauth_diagnostic"}
    ]
    policy = ast.ClassDef(name="DiagnosticPolicy", bases=[], keywords=[], body=methods, decorator_list=[])
    namespace = {
        "hashlib": hashlib,
        "re": re,
        "secrets": secrets,
        "MSGOFFICE365_NON_ADMIN_OAUTH_DIAGNOSTIC_STATE": DIAGNOSTIC_STATE_KEY,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[policy], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["DiagnosticPolicy"]


def _load_refresh_token_preserver():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_preserve_prior_refresh_token"
    )
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["_preserve_prior_refresh_token"]


class NonAdminOAuthDiagnosticTests(unittest.TestCase):
    def test_missing_refresh_response_preserves_only_the_prior_refresh_token(self):
        preserve_refresh_token = _load_refresh_token_preserver()
        token_response = {"access_token": "new-access-token"}

        preserved = preserve_refresh_token(token_response, "prior-refresh-token", "refresh_token")

        self.assertTrue(preserved)
        self.assertEqual(token_response, {"access_token": "new-access-token", "refresh_token": "prior-refresh-token"})

    def test_refresh_token_preservation_does_not_apply_to_other_response_cases(self):
        preserve_refresh_token = _load_refresh_token_preserver()

        cases = (
            ({"access_token": "new", "refresh_token": "replacement"}, "prior", "refresh_token"),
            ({"access_token": "new"}, None, "refresh_token"),
            ({"access_token": "new"}, "prior", "authorization_code"),
        )
        for token_response, prior_refresh_token, token_source in cases:
            with self.subTest(token_response=token_response, token_source=token_source):
                original_response = token_response.copy()
                self.assertFalse(preserve_refresh_token(token_response, prior_refresh_token, token_source))
                self.assertEqual(token_response, original_response)

    def test_diagnostic_is_stable_and_never_logs_credential_values(self):
        policy = _load_diagnostic_policy()

        class Harness(policy):
            def __init__(self):
                self._state = {
                    "code": "authorization-code-value",
                    "non_admin_auth": {
                        "access_token": "access-token-value",
                        "refresh_token": "refresh-token-value",
                    },
                }
                self.debug_messages = []

            def debug_print(self, message):
                self.debug_messages.append(message)

        harness = Harness()
        harness._record_non_admin_oauth_diagnostic(
            "refresh_token_missing_preserved",
            token_source="refresh_token",
            token_response_refresh_token_present=False,
            prior_refresh_token_present=True,
            refresh_token_preserved=True,
            create_revision=True,
        )

        message = harness.debug_messages[-1]
        self.assertIn("event=refresh_token_missing_preserved", message)
        self.assertIn("token_source=refresh_token", message)
        self.assertIn("token_response_refresh_token_present=False", message)
        self.assertIn("prior_refresh_token_present=True", message)
        self.assertIn("refresh_token_preserved=True", message)
        self.assertRegex(message, r"state_revision_fingerprint=[0-9a-f]{12}")
        for secret_value in ("authorization-code-value", "access-token-value", "refresh-token-value"):
            self.assertNotIn(secret_value, message)

        revision = harness._state[DIAGNOSTIC_STATE_KEY]["revision"]
        self.assertNotIn(revision, message)
        self.assertEqual(harness._get_non_admin_state_revision_fingerprint(), message.split("state_revision_fingerprint=")[1][:12])

    def test_diagnostic_handles_invalid_or_missing_state_without_logging_values(self):
        policy = _load_diagnostic_policy()

        class Harness(policy):
            def __init__(self, state):
                self._state = state
                self.debug_messages = []

            def debug_print(self, message):
                self.debug_messages.append(message)

        for state, expected_fingerprint in (({}, "absent"), ({"non_admin_auth_diagnostic": {"revision": "unsafe value"}}, "invalid")):
            harness = Harness(state)
            harness._record_non_admin_oauth_diagnostic("state_loaded")
            self.assertIn(f"state_revision_fingerprint={expected_fingerprint}", harness.debug_messages[-1])


if __name__ == "__main__":
    unittest.main()
