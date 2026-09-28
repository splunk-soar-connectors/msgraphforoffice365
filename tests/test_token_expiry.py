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
import unittest
from copy import deepcopy
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "office365_connector.py"


def _load_token_policy():
    tree = ast.parse(CONNECTOR.read_text())
    connector = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Office365Connector")
    methods = [node for node in connector.body if isinstance(node, ast.FunctionDef) and node.name in {"_make_rest_call_helper", "_get_token"}]
    policy = ast.ClassDef(name="TokenPolicy", bases=[], keywords=[], body=methods, decorator_list=[])

    class PhantomStub:
        APP_SUCCESS = 0
        APP_ERROR = 1

        @staticmethod
        def is_fail(status):
            return status != PhantomStub.APP_SUCCESS

    class Clock:
        now = 1000

        @classmethod
        def time(cls):
            return cls.now

    namespace = {
        "phantom": PhantomStub,
        "time": Clock,
        "MSGOFFICE365_EXPIRES_IN": "expires_in",
        "MSGOFFICE365_EXPIRES_AT": "expires_at",
        "MSGOFFICE365_TOKEN_EXPIRY_BUFFER": 60,
        "MSGOFFICE365_STATE_FILE_CORRUPT_ERROR": "State file is corrupt",
        "MSGOFFICE365_INVALID_PERMISSION_ERROR": "Token was not saved",
        "MSGOFFICE365_AUTH_FAILURE_MSG": ["InvalidAuthenticationToken"],
        "MSGRAPH_API_URL": "https://graph.microsoft.com",
        "_is_expected_graph_url": lambda url: url.startswith("https://graph.microsoft.com/"),
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[policy], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["TokenPolicy"], PhantomStub, Clock


class ActionResult:
    def __init__(self):
        self.status = 0
        self.message = ""

    def set_status(self, status, message=""):
        self.status = status
        self.message = message
        return status

    def get_status(self):
        return self.status

    def get_message(self):
        return self.message


class TokenExpiryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, cls.phantom, cls.clock = _load_token_policy()

    def setUp(self):
        self.clock.now = 1000

    def _connector(self, state, admin_access, access_token="stored", refresh_status=0, reject_stored=False):
        class Harness(self.policy):
            def __init__(self):
                self._state = state
                self._admin_access = admin_access
                self._access_token = access_token
                self._refresh_token = state.get("non_admin_auth", {}).get("refresh_token")
                self._auth_type = "oauth"
                self._client_secret = object()
                self.refresh_calls = 0
                self.requests = []

            def save_progress(self, message):
                pass

            def debug_print(self, *args):
                pass

            def _get_token(self, action_result):
                self.refresh_calls += 1
                if refresh_status:
                    return action_result.set_status(refresh_status, "Token refresh failed")
                self._access_token = "refreshed"
                return self.phantom.APP_SUCCESS

            def _make_rest_call(self, action_result, url, verify, headers, params, data, method, **kwargs):
                self.requests.append((url, headers.copy(), kwargs))
                if reject_stored and headers["Authorization"] == "Bearer stored":
                    return action_result.set_status(self.phantom.APP_ERROR, "InvalidAuthenticationToken. Invalid token lifetime."), None
                return self.phantom.APP_SUCCESS, {"value": []}

        Harness.phantom = self.phantom
        return Harness()

    def test_valid_token_is_reused(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 2000}}, False)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(response, {"value": []})
        self.assertEqual(connector.refresh_calls, 0)
        self.assertEqual(connector.requests[0][1]["Authorization"], "Bearer stored")

    def test_early_graph_rejection_refreshes_and_retries_once(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 2000}}, False, reject_stored=True)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(response, {"value": []})
        self.assertEqual(connector.refresh_calls, 1)
        self.assertEqual([request[1]["Authorization"] for request in connector.requests], ["Bearer stored", "Bearer refreshed"])

    def test_old_auth_message_does_not_repeat_successful_request(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 2000}}, False)
        action_result = ActionResult()
        action_result.set_status(self.phantom.APP_ERROR, "InvalidAuthenticationToken")

        status, response = connector._make_rest_call_helper(action_result, "/users", method="post")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(response, {"value": []})
        self.assertEqual(connector.refresh_calls, 0)
        self.assertEqual(len(connector.requests), 1)

    def test_admin_token_expiry_is_checked_against_admin_state(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 2000}, "admin_auth": {"expires_at": 900}}, True)

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(connector.refresh_calls, 1)
        self.assertEqual(connector.requests[0][1]["Authorization"], "Bearer refreshed")

    def test_legacy_token_without_expiry_is_reused(self):
        connector = self._connector({"non_admin_auth": {"access_token": "stored", "refresh_token": "renewal"}}, False)

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(connector.refresh_calls, 0)
        self.assertEqual(connector.requests[0][1]["Authorization"], "Bearer stored")

    def test_legacy_token_is_refreshed_after_graph_rejection(self):
        connector = self._connector({"non_admin_auth": {"access_token": "stored", "refresh_token": "renewal"}}, False, reject_stored=True)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(response, {"value": []})
        self.assertEqual(connector.refresh_calls, 1)
        self.assertEqual([request[1]["Authorization"] for request in connector.requests], ["Bearer stored", "Bearer refreshed"])

    def test_legacy_token_without_refresh_credentials_is_reused(self):
        connector = self._connector({"non_admin_auth": {"access_token": "stored"}}, False)

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(connector.refresh_calls, 0)
        self.assertEqual(connector.requests[0][1]["Authorization"], "Bearer stored")

    def test_failed_refresh_stops_graph_request(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 900}}, False, refresh_status=self.phantom.APP_ERROR)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_ERROR)
        self.assertIsNone(response)
        self.assertEqual(connector.refresh_calls, 1)
        self.assertFalse(connector.requests)

    def test_unexpected_pagination_url_does_not_refresh_token(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 900}}, False)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users", nextLink="https://example.com/users")

        self.assertEqual(status, self.phantom.APP_ERROR)
        self.assertIsNone(response)
        self.assertEqual(connector.refresh_calls, 0)
        self.assertFalse(connector.requests)

    def test_pagination_request_disables_redirects(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 2000}}, False)

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users", nextLink="https://graph.microsoft.com/v1.0/users?$skiptoken=next")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertFalse(connector.requests[0][2]["allow_redirects"])

    def test_saved_expiry_uses_token_request_start_time(self):
        clock = self.clock

        class Harness(self.policy):
            def __init__(self):
                self._auth_type = "oauth"
                self._client_secret = "configured"  # pragma: allowlist secret
                self._admin_access = False
                self._admin_consent = False
                self._state = {}
                self.saved_state = {}

            def _generate_new_oauth_access_token(self, action_result):
                clock.now = 1030
                return 0, {"access_token": "new", "expires_in": 3600}

            def save_state(self, state):
                self.saved_state = deepcopy(state)

            def load_state(self):
                return deepcopy(self.saved_state)

            def debug_print(self, message):
                pass

        connector = Harness()

        status = connector._get_token(ActionResult())

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(connector.saved_state["non_admin_auth"]["expires_at"], 4540)
