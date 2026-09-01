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
import unittest
import urllib.parse
from copy import deepcopy
from datetime import datetime
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "office365_connector.py"


def _load_quote_helper():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_quote_path_segment")
    namespace = {"urllib": urllib}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["_quote_path_segment"]


def _load_redirect_helper():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_is_redirect_status")
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["_is_redirect_status"]


def _load_non_admin_state_revision_helper():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    connector = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Office365Connector")
    helper = next(
        node for node in connector.body if isinstance(node, ast.FunctionDef) and node.name == "_get_non_admin_state_revision_fingerprint"
    )
    namespace = {"hashlib": hashlib, "re": re}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["_get_non_admin_state_revision_fingerprint"]


def _load_polling_policy():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    connector = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Office365Connector")
    methods = [
        node
        for node in connector.body
        if isinstance(node, ast.FunctionDef) and node.name in {"_clear_latest_first_poll_state", "_handle_latest_first_poll"}
    ]
    policy = ast.ClassDef(
        name="PollingPolicy",
        bases=[],
        keywords=[],
        body=methods,
        decorator_list=[],
    )

    class PhantomStub:
        APP_SUCCESS = 0
        APP_ERROR = 1

        @staticmethod
        def is_fail(status):
            return status != PhantomStub.APP_SUCCESS

    namespace = {
        "deepcopy": deepcopy,
        "datetime": datetime,
        "phantom": PhantomStub,
        "O365_TIME_FORMAT": "%Y-%m-%dT%H:%M:%SZ",
        "MSGOFFICE365_LATEST_FIRST_NEXT_LINK": "latest_first_next_link",
        "MSGOFFICE365_LATEST_FIRST_HIGH_WATER": "latest_first_high_water",
        "MSGOFFICE365_LATEST_FIRST_SCOPE": "latest_first_scope",
        "MSGOFFICE365_LATEST_FIRST_PAGE_SIZE": "latest_first_page_size",
        "MSGOFFICE365_PER_PAGE_COUNT": 999,
        "MSGOFFICE365_MAX_POLL_CYCLES": 100,
        "MSGOFFICE365_NO_DATA_FOUND": "No data found",
        "_get_error_msg_from_exception": lambda error, connector: str(error),
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[policy], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["PollingPolicy"], PhantomStub


def _load_rest_call_policy():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    connector = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Office365Connector")
    method = next(node for node in connector.body if isinstance(node, ast.FunctionDef) and node.name == "_make_rest_call")
    policy = ast.ClassDef(
        name="RestCallPolicy",
        bases=[],
        keywords=[],
        body=[method],
        decorator_list=[],
    )

    class PhantomStub:
        APP_SUCCESS = 0
        APP_ERROR = 1

    class RequestsStub:
        def __init__(self):
            self.kwargs = None

        def get(self, url, **kwargs):
            self.kwargs = kwargs
            return type("Response", (), {"status_code": 302})()

    requests_stub = RequestsStub()
    namespace = {
        "requests": requests_stub,
        "phantom": PhantomStub,
        "RetVal": lambda *values: values,
        "_is_redirect_status": lambda status_code: 300 <= status_code < 400,
        "MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT": 30,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[policy], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["RestCallPolicy"], requests_stub, PhantomStub


def _load_oauth_start_handler(initial_state):
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    handler = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_handle_oauth_start")
    state_store = deepcopy(initial_state)
    saved_states = []

    class HttpResponseStub:
        def __init__(self, body="", content_type=None, status=200):
            self.body = body
            self.content_type = content_type
            self.status_code = status
            self.headers = {}

        def __setitem__(self, key, value):
            self.headers[key] = value

    class PhantomStub:
        APP_SUCCESS = 0

    def load_state(asset_id):
        return deepcopy(state_store)

    def save_state(state, asset_id):
        state_store.clear()
        state_store.update(deepcopy(state))
        saved_states.append(deepcopy(state))
        return PhantomStub.APP_SUCCESS

    namespace = {
        "hmac": __import__("hmac"),
        "HttpResponse": HttpResponseStub,
        "phantom": PhantomStub,
        "_load_app_state": load_state,
        "_save_app_state": save_state,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[handler], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["_handle_oauth_start"], state_store, saved_states


class PollingActionResult:
    def __init__(self):
        self.status = 0
        self.message = ""

    def set_status(self, status, message=""):
        self.status = status
        self.message = message
        return status

    def get_status(self):
        return self.status


class RestCallActionResult:
    def __init__(self):
        self.status = 0
        self.message = ""

    def set_status(self, status, message=""):
        self.status = status
        self.message = message
        return status


class ValidationFollowupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.quote_segment = staticmethod(_load_quote_helper())
        cls.is_redirect_status = staticmethod(_load_redirect_helper())

    def test_path_helper_rejects_dot_segments_after_repeated_decoding(self):
        for value in (".", "..", "%2e", "%2e%2e", "%252e%252e", "%25252e%25252e"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.quote_segment(value)

    def test_path_helper_preserves_opaque_identifier_encoding(self):
        self.assertEqual(self.quote_segment("user/name"), "user%2Fname")
        self.assertEqual(self.quote_segment("opaque id"), "opaque%20id")

    def test_attachment_upload_disables_redirects(self):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_upload_large_attachment")
        put_calls = [
            node for node in ast.walk(handler) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "put"
        ]
        self.assertEqual(len(put_calls), 1)
        redirect_keyword = next((keyword for keyword in put_calls[0].keywords if keyword.arg == "allow_redirects"), None)
        self.assertIsNotNone(redirect_keyword)
        self.assertIsInstance(redirect_keyword.value, ast.Constant)
        self.assertIs(redirect_keyword.value.value, False)

    def test_attachment_upload_rejects_every_redirect_response(self):
        for status_code in (300, 301, 302, 303, 307, 308, 399):
            with self.subTest(status_code=status_code):
                self.assertTrue(self.is_redirect_status(status_code))
        for status_code in (200, 299, 400, 429, 500):
            with self.subTest(status_code=status_code):
                self.assertFalse(self.is_redirect_status(status_code))

        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_upload_large_attachment")
        handler_source = ast.get_source_segment(source, handler)
        self.assertLess(handler_source.index("_is_redirect_status(response.status_code)"), handler_source.index("if not response.ok"))

    def test_pagination_get_rejects_redirect_without_following_it(self):
        rest_call_policy, requests_stub, phantom_stub = _load_rest_call_policy()

        class Harness(rest_call_policy):
            _number_of_retries = 1

        action_result = RestCallActionResult()
        status, response = Harness()._make_rest_call(
            action_result,
            "https://graph.microsoft.com/v1.0/messages?$skiptoken=next",
            allow_redirects=False,
        )

        self.assertEqual(status, phantom_stub.APP_ERROR)
        self.assertIsNone(response)
        self.assertFalse(requests_stub.kwargs["allow_redirects"])
        self.assertIn("Refusing to follow a redirect", action_result.message)

    def test_next_link_calls_disable_redirects_including_token_retry(self):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        helper = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_make_rest_call_helper")
        rest_calls = [
            node
            for node in ast.walk(helper)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "_make_rest_call"
        ]

        self.assertEqual(len(rest_calls), 2)
        for call in rest_calls:
            redirect_keyword = next((keyword for keyword in call.keywords if keyword.arg == "allow_redirects"), None)
            self.assertIsNotNone(redirect_keyword)
            self.assertEqual(ast.unparse(redirect_keyword.value), "not bool(nextLink)")

    def test_oauth_start_requires_and_consumes_one_time_nonce(self):
        handler, state_store, saved_states = _load_oauth_start_handler(
            {
                "start_nonce": "unguessable-start-nonce",
                "flow_nonce": "provider-callback-nonce",
                "admin_consent_url": "https://login.microsoftonline.com/tenant/adminconsent?state=secret",
            }
        )

        request = type("Request", (), {"GET": {"asset_id": "123", "start_nonce": "wrong"}})()
        rejected = handler(request, [])
        self.assertEqual(rejected.status_code, 400)
        self.assertFalse(saved_states)
        self.assertIn("start_nonce", state_store)

        request.GET["start_nonce"] = "unguessable-start-nonce"
        accepted = handler(request, [])
        self.assertEqual(accepted.status_code, 302)
        self.assertEqual(accepted.headers["Location"], state_store["admin_consent_url"])
        self.assertNotIn("start_nonce", state_store)
        self.assertEqual(len(saved_states), 1)

        replayed = handler(request, [])
        self.assertEqual(replayed.status_code, 400)
        self.assertEqual(len(saved_states), 1)

    def test_generated_oauth_start_url_includes_nonce(self):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_get_consent")
        handler_source = ast.get_source_segment(source, handler)

        self.assertIn('app_state["start_nonce"] = start_nonce', handler_source)
        self.assertIn('"start_nonce": start_nonce', handler_source)
        self.assertLess(handler_source.index('app_state["start_nonce"]'), handler_source.index("_save_app_state(app_state"))

    def test_latest_first_poll_persists_continuation_before_checkpoint(self):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_handle_latest_first_poll")
        handler_source = ast.get_source_segment(source, handler)

        continuation_offset = handler_source.index("self._state[MSGOFFICE365_LATEST_FIRST_NEXT_LINK] = next_link")
        continuation_save_offset = handler_source.index("self.save_state(deepcopy(self._state))", continuation_offset)
        checkpoint_offset = handler_source.index('self._state["last_time"] = high_water')
        clear_offset = handler_source.index("self._clear_latest_first_poll_state()", continuation_save_offset)

        self.assertLess(continuation_offset, continuation_save_offset)
        self.assertLess(continuation_save_offset, clear_offset)
        self.assertLess(clear_offset, checkpoint_offset)
        self.assertIn("if failed_email_ids:", handler_source[:continuation_offset])
        self.assertIn("if next_link:", handler_source[:continuation_offset])
        self.assertIn("processed + page_size > poll_budget", handler_source)

    def test_latest_first_poll_resumes_before_committing_high_water(self):
        polling_policy, phantom_stub = _load_polling_policy()

        class Harness(polling_policy):
            def __init__(self):
                self._state = {"first_run": True}
                self.pages = []
                self.saved_states = []
                self.processed_ids = []
                self.failed_ids = set()

            def _fetch_poll_page(self, action_result, endpoint, params=None, next_link=None):
                return self.pages.pop(0)

            def _process_email_data(self, config, action_result, endpoint, email):
                self.processed_ids.append(email["id"])
                if email["id"] in self.failed_ids:
                    return phantom_stub.APP_ERROR
                return phantom_stub.APP_SUCCESS

            def save_state(self, state):
                self.saved_states.append(deepcopy(state))

            def send_progress(self, message):
                pass

            def debug_print(self, message):
                pass

        harness = Harness()
        action_result = PollingActionResult()
        harness.pages = [
            (
                phantom_stub.APP_SUCCESS,
                [
                    {"id": "newest", "lastModifiedDateTime": "2026-08-01T10:00:00Z"},
                    {"id": "middle", "lastModifiedDateTime": "2026-08-01T09:00:00Z"},
                ],
                "https://graph.microsoft.com/v1.0/messages?$skiptoken=next",
            )
        ]

        status = harness._handle_latest_first_poll(action_result, {}, "/users/u/messages", {"$orderBy": "desc"}, 2)
        self.assertEqual(status, phantom_stub.APP_SUCCESS)
        self.assertEqual(harness.processed_ids, ["newest", "middle"])
        self.assertNotIn("last_time", harness._state)
        self.assertEqual(harness._state["latest_first_high_water"], "2026-08-01T10:00:00Z")
        self.assertIn("latest_first_next_link", harness._state)

        saved_continuation_state = deepcopy(harness._state)
        harness.failed_ids.add("oldest")
        harness.pages = [
            (
                phantom_stub.APP_SUCCESS,
                [{"id": "oldest", "lastModifiedDateTime": "2026-08-01T08:00:00Z"}],
                None,
            )
        ]
        status = harness._handle_latest_first_poll(action_result, {}, "/users/u/messages", {"$orderBy": "desc"}, 2)
        self.assertEqual(status, phantom_stub.APP_ERROR)
        self.assertEqual(harness._state, saved_continuation_state)
        self.assertNotIn("last_time", harness._state)

        harness.failed_ids.clear()
        action_result = PollingActionResult()
        harness.pages = [
            (
                phantom_stub.APP_SUCCESS,
                [{"id": "oldest", "lastModifiedDateTime": "2026-08-01T08:00:00Z"}],
                None,
            )
        ]
        status = harness._handle_latest_first_poll(action_result, {}, "/users/u/messages", {"$orderBy": "desc"}, 2)
        self.assertEqual(status, phantom_stub.APP_SUCCESS)
        self.assertEqual(harness.processed_ids, ["newest", "middle", "oldest", "oldest"])
        self.assertEqual(harness._state["last_time"], "2026-08-01T10:00:00Z")
        self.assertFalse(harness._state["first_run"])
        self.assertNotIn("latest_first_next_link", harness._state)
        self.assertNotIn("latest_first_high_water", harness._state)

    def test_container_completion_marker_is_written_only_after_artifacts(self):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_process_email_data")
        handler_source = ast.get_source_segment(source, handler)
        save_artifacts_offset = handler_source.index("self.save_artifacts(artifacts)")
        completed_offset = handler_source.index('container["data"]["ingestion_complete"] = True')
        update_offset = handler_source.index("self._update_container(action_result, container_id, container)")

        self.assertIn('"ingestion_complete": False', handler_source[:save_artifacts_offset])
        self.assertIn('container_data.get("ingestion_complete") is True', handler_source[:save_artifacts_offset])
        self.assertLess(save_artifacts_offset, completed_offset)
        self.assertLess(completed_offset, update_offset)

    def test_non_admin_oauth_diagnostics_only_report_token_presence(self):
        source = CONNECTOR.read_text()

        for message in (
            "Non-admin OAuth state loaded: non_admin_auth_present={}, access_token_present={}, refresh_token_present={}, ",
            "Non-admin OAuth token source check: authorization_code_present={}, refresh_token_present={}",
            "Non-admin OAuth token response: token_source={}, access_token_present={}, refresh_token_present={}",
            "Non-admin OAuth state persistence check: access_token_persisted={}, refresh_token_persisted={}, ",
            "Non-admin OAuth authorization request: offline_access_requested={}",
        ):
            self.assertIn(message, source)

        self.assertIn(
            "Non-admin OAuth token generation cannot continue: no authorization code or refresh token is available in state",
            source,
        )

    def test_non_admin_state_revision_fingerprint_is_safe_and_stable(self):
        helper = _load_non_admin_state_revision_helper()
        connector = type("Connector", (), {"_state": {"non_admin_auth_diagnostic": {"revision": "abcDEF123_-"}}})()

        fingerprint = helper(connector)
        self.assertEqual(fingerprint, helper(connector))
        self.assertEqual(len(fingerprint), 12)
        self.assertNotIn("abcDEF123_-", fingerprint)

        connector._state = {}
        self.assertEqual(helper(connector), "absent")

        connector._state = {"non_admin_auth_diagnostic": {"revision": "not a diagnostic revision"}}
        self.assertEqual(helper(connector), "invalid")


if __name__ == "__main__":
    unittest.main()
