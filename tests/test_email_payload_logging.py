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
import base64
import json
import os
import tempfile
import unittest
from collections import OrderedDict
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
BODY = "PRIVATE-EMAIL-BODY-DO-NOT-LOG"
ATTACHMENT = b"PRIVATE-ATTACHMENT-DO-NOT-LOG"


def _load_methods(path, class_name, methods, namespace):
    tree = ast.parse(path.read_text())
    original = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    policy = ast.ClassDef(
        name=class_name,
        bases=[],
        keywords=[],
        body=[node for node in original.body if isinstance(node, ast.FunctionDef) and node.name in methods],
        decorator_list=[],
    )
    exec(compile(ast.fix_missing_locations(ast.Module(body=[policy], type_ignores=[])), str(path), "exec"), namespace)
    return namespace[class_name]


class ActionResult:
    def __init__(self):
        self.debug_data = []
        self.message = ""

    def add_debug_data(self, value):
        self.debug_data.append(value)

    def set_status(self, status, message):
        self.message = message
        return status


class Response:
    def __init__(self, payload, status=200, content_type="application/json"):
        self.payload = payload
        self.status_code = status
        self.headers = {"Content-Type": content_type, "Set-Cookie": BODY}
        self.url = "https://graph.microsoft.com/v1.0/users/example/messages"

    @property
    def text(self):
        return self.payload if isinstance(self.payload, str) else json.dumps(self.payload)

    def json(self):
        if isinstance(self.payload, str):
            return json.loads(self.payload)
        return self.payload


class ResponseLoggingTests(unittest.TestCase):
    def setUp(self):
        namespace = {
            "phantom": SimpleNamespace(APP_SUCCESS=0, APP_ERROR=1),
            "RetVal": lambda *values: values,
            "_is_token_response": lambda response: "login.microsoftonline.com" in response.url,
            "_get_error_msg_from_exception": lambda error, connector: connector.error_print(error, dump_object=error),
        }
        policy = _load_methods(
            ROOT / "office365_connector.py",
            "Office365Connector",
            {"_process_response", "_process_json_response", "_process_html_response"},
            namespace,
        )
        self.connector = policy()
        self.exception_dumps = []
        self.connector.error_print = lambda *args, **kwargs: self.exception_dumps.append((args, kwargs))

    def assert_redacted(self, result):
        diagnostics = repr((result.debug_data, result.message, self.exception_dumps))
        self.assertNotIn(BODY, diagnostics)
        self.assertLess(len(diagnostics), 2000)

    def test_success_keeps_email_results_without_buffering_response_body(self):
        payload = {"value": [{"body": {"content": BODY * 10000}}]}
        result = ActionResult()
        status, data = self.connector._process_response(Response(payload), result)
        self.assertEqual(status, 0)
        self.assertIs(data, payload)
        self.assert_redacted(result)
        self.assertIn({"r_status_code": 200}, result.debug_data)

    def test_decode_failure_does_not_dump_exception_document(self):
        result = ActionResult()
        status, data = self.connector._process_response(Response(BODY * 10000), result)
        self.assertEqual(status, 1)
        self.assertIsNone(data)
        self.assertFalse(self.exception_dumps)
        self.assert_redacted(result)

    def test_html_and_unknown_content_errors_omit_body(self):
        for content_type in ("text/html", "text/plain"):
            with self.subTest(content_type=content_type):
                result = ActionResult()
                status, data = self.connector._process_response(Response(BODY * 10000, 502, content_type), result)
                self.assertEqual(status, 1)
                self.assertIsNone(data)
                self.assertIn("502", result.message)
                self.assert_redacted(result)

    def test_unrecognized_json_error_does_not_echo_document(self):
        result = ActionResult()
        status, data = self.connector._process_response(Response({"body": BODY * 10000}, 500), result)
        self.assertEqual(status, 1)
        self.assertIsNone(data)
        self.assertIn("500", result.message)
        self.assert_redacted(result)

    def test_token_response_keeps_existing_redaction(self):
        response = Response({"access_token": BODY})
        response.url = "https://login.microsoftonline.com/example/oauth2/v2.0/token"
        result = ActionResult()
        status, data = self.connector._process_response(response, result)
        self.assertEqual(status, 0)
        self.assertEqual(data["access_token"], BODY)
        self.assertIn({"r_text": "<OAuth token response redacted>"}, result.debug_data)
        self.assert_redacted(result)


class EmailParsingLoggingTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "process_email.py"
        namespace = {
            "OrderedDict": OrderedDict,
            "os": os,
            "phantom": SimpleNamespace(APP_SUCCESS=0, APP_ERROR=1, is_fail=lambda status: status != 0),
            "_container_common": {"run_automation": False},
            "_artifact_common": {"run_automation": False},
        }
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.startswith("PROC_EMAIL_JSON_"):
                        namespace[target.id] = ast.literal_eval(node.value)
        policy = _load_methods(path, "ProcessEmail", {"_debug_print", "_handle_mail_object", "_add_artifacts"}, namespace)
        self.parser = policy()
        self.logs = []
        self.parser._base_connector = SimpleNamespace(debug_print=lambda *args: self.logs.append(args))
        self.parser._config = {"extract_attachments": True}
        self.parser._container = {}
        self.parser._attachments = []
        self.parser._parse_email_headers = lambda *args, **kwargs: None
        self.parser._get_container_name = lambda *args: "Test email"
        self.parser._create_artifacts = lambda *args, **kwargs: None
        self.parser._sanitize_dict = lambda value: value

    def test_mime_processing_preserves_content_without_logging_payloads(self):
        mail = EmailMessage()
        mail["Subject"] = "Test"
        mail.set_content(BODY * 10000)
        mail.add_attachment(ATTACHMENT, maintype="application", subtype="octet-stream", filename="test.bin")
        handled = []

        def handle_part(part, *args):
            handled.append(part.get_payload(decode=True))
            return 0

        self.parser._handle_part = handle_part
        raw_email = mail.as_string()
        with tempfile.TemporaryDirectory() as directory:
            status = self.parser._handle_mail_object(mail, "test-id", raw_email, directory, 0)

        self.assertEqual(status, 0)
        self.assertEqual(self.parser._container["data"]["raw_email"], raw_email)
        self.assertIn(ATTACHMENT, handled)
        diagnostics = repr(self.logs)
        self.assertNotIn(BODY, diagnostics)
        self.assertNotIn(base64.b64encode(ATTACHMENT).decode(), diagnostics)
        self.assertLess(len(diagnostics), 2000)

    def test_artifacts_are_preserved_without_logging_cef_values(self):
        artifacts = []
        count = self.parser._add_artifacts([{"body": BODY}], "Email Artifact", 0, artifacts)
        self.assertEqual(count, 1)
        self.assertEqual(artifacts[0]["cef"]["body"], BODY)
        self.assertNotIn(BODY, repr(self.logs))


if __name__ == "__main__":
    unittest.main()
