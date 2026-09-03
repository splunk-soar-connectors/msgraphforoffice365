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


class NonAdminOAuthDiagnosticTests(unittest.TestCase):
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
            "token_response_received",
            token_source="authorization_code",
            token_response_refresh_token_present=True,
            create_revision=True,
        )

        message = harness.debug_messages[-1]
        self.assertIn("event=token_response_received", message)
        self.assertIn("token_source=authorization_code", message)
        self.assertIn("token_response_refresh_token_present=True", message)
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
