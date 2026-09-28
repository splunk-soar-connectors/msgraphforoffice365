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
from runpy import run_path


CONNECTOR = Path(__file__).resolve().parents[1] / "office365_connector.py"


def _load_token_policy():
    tree = ast.parse(CONNECTOR.read_text())
    connector = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Office365Connector")
    methods = [
        node
        for node in connector.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_make_rest_call_helper", "_make_rest_call", "_get_token", "_generate_new_cba_access_token", "finalize"}
    ]
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
        "MSGOFFICE365_CBA_ADMIN_CONSENT_ERROR": "Admin consent is required",
        "MSGOFFICE365_AUTH_FAILURE_MSG": run_path(str(CONNECTOR.with_name("office365_consts.py")))["MSGOFFICE365_AUTH_FAILURE_MSG"],
        "MSGRAPH_API_URL": "https://graph.microsoft.com",
        "MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT": 30,
        "MSGOFFICE365_AUTHORITY_URL": "https://login.microsoftonline.com/{tenant}",
        "MSGOFFICE365_DEFAULT_SCOPE": "https://graph.microsoft.com/.default",
        "RetVal": lambda *values: values,
        "requests": None,
        "msal": None,
        "_is_redirect_status": lambda status_code: 300 <= status_code < 400,
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

    def _connector(
        self,
        state,
        admin_access,
        access_token="stored",
        refresh_status=0,
        reject_stored=False,
        rejection_message="InvalidAuthenticationToken. Invalid token lifetime.",
    ):
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
                return action_result.set_status(self.phantom.APP_SUCCESS)

            def _make_rest_call(self, action_result, url, verify, headers, params, data, method, **kwargs):
                self.requests.append((url, headers.copy(), kwargs))
                if reject_stored and headers["Authorization"] == "Bearer stored":
                    return action_result.set_status(self.phantom.APP_ERROR, rejection_message), None
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

    def test_invalid_saved_expiry_does_not_block_valid_token(self):
        connector = self._connector({"non_admin_auth": {"expires_at": "invalid"}}, False)

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

    def test_invalid_token_lifetime_without_error_code_is_retried(self):
        connector = self._connector(
            {"non_admin_auth": {"access_token": "stored"}}, False, reject_stored=True, rejection_message="Invalid token lifetime"
        )

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(response, {"value": []})
        self.assertEqual(connector.refresh_calls, 1)
        self.assertEqual(len(connector.requests), 2)

    def test_download_auth_error_refreshes_and_retries(self):
        class Response:
            def __init__(self, status_code, content):
                self.status_code = status_code
                self.text = content

        class RequestsStub:
            def __init__(self):
                self.authorization = []

            def get(self, url, **kwargs):
                authorization = kwargs["headers"]["Authorization"]
                self.authorization.append(authorization)
                if authorization == "Bearer stored":
                    return Response(401, "InvalidAuthenticationToken. Invalid token lifetime.")
                return Response(200, "downloaded")

        class Harness(self.policy):
            _number_of_retries = 1

            def __init__(self):
                self._state = {"non_admin_auth": {"access_token": "stored"}}
                self._admin_access = False
                self._access_token = "stored"
                self.refresh_calls = 0

            def save_progress(self, message):
                pass

            def debug_print(self, *args):
                pass

            def _get_token(self, action_result):
                self.refresh_calls += 1
                self._access_token = "fresh"
                return action_result.set_status(0)

            def _process_response(self, response, action_result):
                return action_result.set_status(1, response.text), None

        requests_stub = RequestsStub()
        policy_globals = self.policy._make_rest_call.__globals__
        previous_requests = policy_globals["requests"]
        policy_globals["requests"] = requests_stub
        try:
            action_result = ActionResult()
            connector = Harness()
            status, response = connector._make_rest_call_helper(action_result, "/users/me/messages/1/$value", download=True)
        finally:
            policy_globals["requests"] = previous_requests

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(response, "downloaded")
        self.assertEqual(action_result.get_status(), self.phantom.APP_SUCCESS)
        self.assertEqual(connector.refresh_calls, 1)
        self.assertEqual(requests_stub.authorization, ["Bearer stored", "Bearer fresh"])

    def test_reactive_refresh_failure_stops_retry(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 2000}}, False, reject_stored=True, refresh_status=self.phantom.APP_ERROR)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_ERROR)
        self.assertIsNone(response)
        self.assertEqual(connector.refresh_calls, 1)
        self.assertEqual(len(connector.requests), 1)

    def test_non_auth_graph_failure_does_not_retry(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 2000}}, False, reject_stored=True, rejection_message="BadRequest")

        status, response = connector._make_rest_call_helper(ActionResult(), "/users", method="post")

        self.assertEqual(status, self.phantom.APP_ERROR)
        self.assertIsNone(response)
        self.assertEqual(connector.refresh_calls, 0)
        self.assertEqual(len(connector.requests), 1)

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

    def test_cba_refresh_failure_stops_graph_request(self):
        initial_state = {"admin_auth": {"access_token": "stored", "expires_at": 900}}

        class Harness(self.policy):
            def __init__(self):
                self._state = deepcopy(initial_state)
                self._admin_access = True
                self._auth_type = "automatic"
                self._client_secret = None
                self._thumbprint = "thumbprint"
                self._certificate_private_key = "private_key"  # pragma: allowlist secret
                self._admin_consent = False
                self._access_token = "stored"
                self._initialization_succeeded = True
                self.saved_state = None
                self.requests = []

            def save_progress(self, message):
                pass

            def set_status(self, status):
                return status

            def save_state(self, state):
                self.saved_state = deepcopy(state)

            def _make_rest_call(self, *args, **kwargs):
                self.requests.append((args, kwargs))
                return 0, {"value": []}

        connector = Harness()

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, self.phantom.APP_ERROR)
        self.assertIsNone(response)
        self.assertFalse(connector.requests)
        self.assertEqual(connector._state, initial_state)
        self.assertEqual(connector.finalize(), self.phantom.APP_SUCCESS)
        self.assertEqual(connector.saved_state, initial_state)

    def test_cba_msal_error_preserves_cached_auth_state(self):
        class MsalStub:
            class ConfidentialClientApplication:
                def __init__(self, *args, **kwargs):
                    pass

                def acquire_token_for_client(self, scopes):
                    return {"error": "temporarily_unavailable", "error_description": "Try again later"}

        class Harness(self.policy):
            def __init__(self):
                self._state = {"admin_auth": {"access_token": "stored"}, "non_admin_auth": {"access_token": "other"}}
                self._thumbprint = "thumbprint"
                self._certificate_private_key = "private_key"  # pragma: allowlist secret
                self._admin_consent = True
                self._client_id = "client"
                self._tenant = "tenant"

            def save_progress(self, message):
                pass

            def debug_print(self, message):
                pass

            def _get_private_key(self, action_result):
                return 0, "key"

        policy_globals = self.policy._generate_new_cba_access_token.__globals__
        previous_msal = policy_globals["msal"]
        policy_globals["msal"] = MsalStub
        try:
            connector = Harness()
            initial_state = deepcopy(connector._state)
            status, response = connector._generate_new_cba_access_token(ActionResult())
        finally:
            policy_globals["msal"] = previous_msal

        self.assertEqual(status, self.phantom.APP_ERROR)
        self.assertIsNone(response)
        self.assertEqual(connector._state, initial_state)

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

    def test_pagination_retry_disables_redirects(self):
        connector = self._connector({"non_admin_auth": {"expires_at": 2000}}, False, reject_stored=True)

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users", nextLink="https://graph.microsoft.com/v1.0/users?$skiptoken=next")

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(len(connector.requests), 2)
        self.assertTrue(all(not request[2]["allow_redirects"] for request in connector.requests))

    def test_saved_expiry_uses_token_request_start_time(self):
        clock = self.clock

        class Harness(self.policy):
            def __init__(self, expires_in=3600):
                self._auth_type = "oauth"
                self._client_secret = "configured"  # pragma: allowlist secret
                self._admin_access = False
                self._admin_consent = False
                self._state = {}
                self.saved_state = {}
                self.expires_in = expires_in

            def _generate_new_oauth_access_token(self, action_result):
                clock.now = 1030
                return 0, {"access_token": "new", "expires_in": self.expires_in}

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

        malformed_connector = Harness("invalid")
        status = malformed_connector._get_token(ActionResult())

        self.assertEqual(status, self.phantom.APP_SUCCESS)
        self.assertEqual(malformed_connector.saved_state["non_admin_auth"]["access_token"], "new")
        self.assertNotIn("expires_at", malformed_connector.saved_state["non_admin_auth"])

    def test_expired_oauth_and_cba_tokens_use_persisted_refresh(self):
        class Harness(self.policy):
            def __init__(self, auth_type):
                self._auth_type = auth_type
                self._client_secret = None if auth_type == "cba" else "configured"  # pragma: allowlist secret
                self._admin_access = auth_type == "cba"
                self._admin_consent = self._admin_access
                self._refresh_token = "renewal"
                self._access_token = "stored"
                self.state_key = "admin_auth" if self._admin_access else "non_admin_auth"
                self._state = {self.state_key: {"access_token": "stored", "expires_at": 900}}
                self.saved_state = {}
                self.requests = []
                self.token_requests = 0

            def _generate_new_oauth_access_token(self, action_result):
                self.token_requests += 1
                return 0, {"access_token": "refreshed", "refresh_token": "renewal", "expires_in": 3600}

            def _generate_new_cba_access_token(self, action_result):
                self.token_requests += 1
                return 0, {"access_token": "refreshed", "expires_in": 3600}

            def save_state(self, state):
                self.saved_state = deepcopy(state)

            def load_state(self):
                return deepcopy(self.saved_state)

            def save_progress(self, message):
                pass

            def debug_print(self, message):
                pass

            def _make_rest_call(self, action_result, url, verify, headers, params, data, method, **kwargs):
                self.requests.append(headers.copy())
                return 0, {"value": []}

        for auth_type in ("oauth", "cba"):
            with self.subTest(auth_type=auth_type):
                connector = Harness(auth_type)

                status, response = connector._make_rest_call_helper(ActionResult(), "/users")

                self.assertEqual(status, self.phantom.APP_SUCCESS)
                self.assertEqual(response, {"value": []})
                self.assertEqual(connector.token_requests, 1)
                self.assertEqual(connector.requests[0]["Authorization"], "Bearer refreshed")
                self.assertEqual(connector.saved_state[connector.state_key]["expires_at"], 4540)
