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
import urllib.parse
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "office365_connector.py"


def _load_quote_helper():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_quote_path_segment")
    namespace = {"urllib": urllib}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["_quote_path_segment"]


class ValidationFollowupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.quote_segment = staticmethod(_load_quote_helper())

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


if __name__ == "__main__":
    unittest.main()
