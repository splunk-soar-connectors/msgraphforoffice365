# File: office365_connector.py
#
# Copyright (c) 2017-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
import base64
import grp
import json
import os
import pathlib
import pwd
import re
import sys
import tempfile
import time
from copy import deepcopy
from datetime import datetime

import encryption_helper
import msal
import phantom.app as phantom
import phantom.rules as ph_rules
import phantom.utils as util
import phantom.vault as phantom_vault
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from django.http import HttpResponse
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault

from office365_consts import *
from process_email import ProcessEmail


TC_FILE = "oauth_task.out"
SERVER_TOKEN_URL = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token"
MSGOFFICE365_AUTHORITY_URL = "https://login.microsoftonline.com/{tenant}"
MSGRAPH_API_URL = "https://graph.microsoft.com"
MAX_END_OFFSET_VAL = 2147483646
MSGOFFICE365_DEFAULT_SCOPE = "https://graph.microsoft.com/.default"


class ReturnException(Exception):
    pass


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


def _load_app_state(asset_id, app_connector=None):
    """This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print("In _load_app_state: Invalid asset_id")
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = f"{app_dir}/{asset_id}_state.json"
    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print("In _load_app_state: Invalid asset_id")
        return {}

    state = {}
    try:
        with open(real_state_file_path) as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            error_msg = _get_error_msg_from_exception(e, app_connector)
            app_connector.debug_print(f"In _load_app_state: {error_msg}")

    if app_connector:
        app_connector.debug_print("Loaded state: ", state)

    try:
        if "code" in state:
            state["code"] = encryption_helper.decrypt(state["code"], asset_id)
    except Exception as e:
        if app_connector:
            error_msg = _get_error_msg_from_exception(e, app_connector)
            app_connector.debug_print(f"{MSGOFFICE365_DECRYPTION_ERROR}: {error_msg}")
        state = {}

    return state


def _save_app_state(state, asset_id, app_connector=None):
    """This function is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print("In _save_app_state: Invalid asset_id")
        return {}

    app_dir = os.path.split(__file__)[0]
    state_file = f"{app_dir}/{asset_id}_state.json"

    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print("In _save_app_state: Invalid asset_id")
        return {}

    try:
        if "code" in state:
            state["code"] = encryption_helper.encrypt(state["code"], asset_id)
    except Exception as e:
        if app_connector:
            error_msg = _get_error_msg_from_exception(e, app_connector)
            app_connector.debug_print(f"{MSGOFFICE365_ENCRYPTION_ERROR}: {error_msg}")

    if app_connector:
        app_connector.debug_print("Saving state: ", state)

    try:
        with open(real_state_file_path, "w+") as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        error_msg = _get_error_msg_from_exception(e, app_connector)
        if app_connector:
            app_connector.debug_print(f"Unable to save state file: {error_msg}")
        print(f"Unable to save state file: {error_msg}")
        return phantom.APP_ERROR

    return phantom.APP_SUCCESS


def _get_error_msg_from_exception(e, app_connector=None):
    """
    Get appropriate error message from the exception.
    :param e: Exception object
    :return: error message
    """
    error_code = None
    error_msg = MSGOFFICE365_ERROR_MSG_UNAVAILABLE
    if app_connector:
        app_connector.error_print("Error occurred.", dump_object=e)

    try:
        if hasattr(e, "args"):
            if len(e.args) > 1:
                error_code = e.args[0]
                error_msg = e.args[1]
            elif len(e.args) == 1:
                error_msg = e.args[0]
    except Exception:
        pass

    if not error_code:
        error_text = f"Error Message: {error_msg}"
    else:
        error_text = f"Error Code: {error_code}. Error Message: {error_msg}"
    if app_connector:
        app_connector.error_print(f"{error_text}")
    return error_text


def _validate_integer(action_result, parameter, key, allow_zero=False):
    """
    Validate an integer.

    :param action_result: Action result or BaseConnector object
    :param parameter: input parameter
    :param key: input parameter message key
    :allow_zero: whether zero should be considered as valid value or not
    :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
    """
    if parameter is not None:
        try:
            if not float(parameter).is_integer():
                return (
                    action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_VALID_INT_MSG.format(param=key)),
                    None,
                )

            parameter = int(parameter)
        except Exception:
            return (
                action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_VALID_INT_MSG.format(param=key)),
                None,
            )

        if parameter < 0:
            return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        if not allow_zero and parameter == 0:
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    MSGOFFICE365_NON_NEG_NON_ZERO_INT_MSG.format(param=key),
                ),
                None,
            )

    return phantom.APP_SUCCESS, parameter


def _handle_oauth_result(request, path_parts):
    """
    <base_url>?admin_consent=True&tenant=a417c578-c7ee-480d-a225-d48057e74df5&state=13
    """
    asset_id = request.GET.get("state")
    if not asset_id:
        return HttpResponse(
            f"ERROR: Asset ID not found in URL\n{json.dumps(request.GET)}",
            content_type="text/plain",
            status=400,
        )

    # first check for error info
    error = request.GET.get("error")
    error_description = request.GET.get("error_description")

    if error:
        msg = f"Error: {error}"
        if error_description:
            msg += f" Details: {error_description}"
        return HttpResponse(f"Server returned {msg}", content_type="text/plain", status=400)

    admin_consent = request.GET.get("admin_consent")
    code = request.GET.get("code")

    if not admin_consent and not code:
        return HttpResponse(
            f"ERROR: admin_consent or authorization code not found in URL\n{json.dumps(request.GET)}",
            content_type="text/plain",
            status=400,
        )

    # Load the data
    state = _load_app_state(asset_id)

    if admin_consent:
        if admin_consent == "True":
            admin_consent = True
        else:
            admin_consent = False

        state["admin_consent"] = admin_consent
        _save_app_state(state, asset_id)

        # If admin_consent is True
        if admin_consent:
            return HttpResponse(
                "Admin Consent received. Please close this window.",
                content_type="text/plain",
            )
        return HttpResponse(
            "Admin Consent declined. Please close this window and try again later.",
            content_type="text/plain",
            status=400,
        )

    # If value of admin_consent is not available, value of code is available
    state["code"] = code
    _save_app_state(state, asset_id)

    return HttpResponse(
        "Code received. Please close this window, the action will continue to get new token.",
        content_type="text/plain",
    )


def _handle_oauth_start(request, path_parts):
    # get the asset id, the state file is created for each asset
    asset_id = request.GET.get("asset_id")
    if not asset_id:
        return HttpResponse("ERROR: Asset ID not found in URL", content_type="text/plain", status=404)

    # Load the state that was created for the asset
    state = _load_app_state(asset_id)
    if not state:
        return HttpResponse(
            "ERROR: The asset ID is invalid or an error occurred while reading the state file",
            content_type="text/plain",
            status=400,
        )

    # get the url to point to the authorize url of OAuth
    admin_consent_url = state.get("admin_consent_url")

    if not admin_consent_url:
        return HttpResponse(
            "App state is invalid, admin_consent_url key not found",
            content_type="text/plain",
            status=400,
        )

    # Redirect to this link, the user will then require to enter credentials interactively
    response = HttpResponse(status=302)
    response["Location"] = admin_consent_url

    return response


def handle_request(request, path_parts):
    """
    request contains the data posted to the rest endpoint, it is the django http request object
    path_parts is a list of the URL tokenized
    """

    # get the type of data requested, it's the last part of the URL used to post to the REST endpoint
    if len(path_parts) < 2:
        return HttpResponse(
            "error: True, message: Invalid REST endpoint request",
            content_type="text/plain",
            status=404,
        )

    call_type = path_parts[1]

    if call_type == "start_oauth":
        # start the authentication process
        return _handle_oauth_start(request, path_parts)

    if call_type == "result":
        # process the 'code'
        ret_val = _handle_oauth_result(request, path_parts)
        asset_id = request.GET.get("state")  # nosemgrep
        if asset_id and asset_id.isalnum():
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = f"{app_dir}/{asset_id}_{TC_FILE}"
            real_auth_status_file_path = os.path.abspath(auth_status_file_path)
            if not os.path.dirname(real_auth_status_file_path) == app_dir:
                return HttpResponse("Error: Invalid asset_id", content_type="text/plain", status=400)
            open(auth_status_file_path, "w").close()
            try:
                uid = pwd.getpwnam("apache").pw_uid
                gid = grp.getgrnam("phantom").gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, "0664")
            except Exception:
                pass

        return ret_val

    return HttpResponse("error: Invalid endpoint", content_type="text/plain", status=404)


def _get_dir_name_from_app_name(app_name):
    app_name = "".join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()

    if not app_name:
        # hardcode it
        app_name = "app_for_phantom"

    return app_name


class Office365Connector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._tenant = None
        self._client_id = None
        self._auth_type = None
        self._client_secret = None
        self._admin_access = None
        self._scope = None
        self._access_token = None
        self._refresh_token = None
        self._REPLACE_CONST = "C53CEA8298BD401BA695F247633D0542"  # pragma: allowlist secret
        self._duplicate_count = 0
        self._asset_id = None
        self._cba_auth = None
        self._private_key = None
        self._certificate_private_key = None

    def load_state(self):
        """
        Load the contents of the state file to the state dictionary and decrypt it.

        :return: loaded state
        """
        state = super().load_state()
        if not isinstance(state, dict):
            self.debug_print("Resetting the state file with the default format")
            state = {"app_version": self.get_app_json().get("app_version")}
            return state
        return self._decrypt_state(state)

    def save_state(self, state):
        """
        Encrypt and save the current state dictionary to the state file.

        :param state: state dictionary
        :return: status
        """
        return super().save_state(self._encrypt_state(state))

    def update_state_fields(self, value, helper_function, error_message):
        try:
            return helper_function(value, self._asset_id)
        except Exception as ex:
            self.debug_print(f"{error_message}: {_get_error_msg_from_exception(ex, self)}")
        return None

    def check_state_fields(self, state, helper_function, error_message):
        access_token = state.get("non_admin_auth", {}).get("access_token")
        if access_token:
            state["non_admin_auth"]["access_token"] = self.update_state_fields(access_token, helper_function, error_message)
        refresh_token = state.get("non_admin_auth", {}).get("refresh_token")
        if refresh_token:
            state["non_admin_auth"]["refresh_token"] = self.update_state_fields(refresh_token, helper_function, error_message)
        access_token = state.get("admin_auth", {}).get("access_token")
        if access_token:
            state["admin_auth"]["access_token"] = self.update_state_fields(access_token, helper_function, error_message)
        return state

    def _decrypt_state(self, state):
        """
        Decrypts the state.

        :param state: state dictionary
        :return: decrypted state
        """
        if not state.get("is_encrypted"):
            return state
        return self.check_state_fields(state, encryption_helper.decrypt, MSGOFFICE365_DECRYPTION_ERROR)

    def _encrypt_state(self, state):
        """
        Encrypts the state.

        :param state: state dictionary
        :return: encrypted state
        """

        state = self.check_state_fields(state, encryption_helper.encrypt, MSGOFFICE365_ENCRYPTION_ERROR)
        state["is_encrypted"] = True

        return state

    def _dump_error_log(self, error, msg="Exception occurred."):
        self.error_print(msg, dump_object=error)

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_ERROR_EMPTY_RESPONSE.format(code=response.status_code)), None)

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        msg = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        msg = msg.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = _get_error_msg_from_exception(e, self)
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Unable to parse JSON response. {error_msg}"), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        try:
            error_code = ""
            error_text = ""

            error_msg = ""
            error = resp_json.get("error", "")
            error_desc = resp_json.get("error_description", "")
            if isinstance(error, dict):
                error_code = error.get("code")
                error_msg = error.get("message")

            if error_msg:
                try:
                    soup = BeautifulSoup(resp_json.get("error", {}).get("message"), "html.parser")
                    # Remove the script, style, footer and navigation part from the HTML message
                    for element in soup(["script", "style", "footer", "nav"]):
                        element.extract()
                    error_text = soup.text
                    split_lines = error_text.split("\n")
                    split_lines = [x.strip() for x in split_lines if x.strip()]
                    error_text = "\n".join(split_lines)
                    if len(error_text) > 500:
                        error_text = "Error while connecting to a server (Please check input parameters or asset configuration parameters)"
                except Exception:
                    error_text = "Cannot parse error details"

            if error_code:
                error_text = f"{error_code}. {error_text}"

            if error_desc:
                error_text = f"{error_desc}. {error_text}"

            if not error_text:
                error_text = r.text.replace("{", "{{").replace("}", "}}")
        except Exception:
            error_text = r.text.replace("{", "{{").replace("}", "}}")

        # You should process the error returned in the json

        msg = f"Error: Status Code: {r.status_code} Data from server: {error_text}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        content_type = r.headers.get("Content-Type", "")
        if "json" in content_type or "javascript" in content_type:
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between Splunk SOAR and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        if r.status_code == 404:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Email not found"), None)

        if 200 <= r.status_code <= 204:
            return RetVal(phantom.APP_SUCCESS, None)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point

        msg = "Can't process response from server. Status Code: {} Data from server: {}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

    def _make_rest_call(
        self,
        action_result,
        url,
        verify=True,
        headers={},
        params=None,
        data=None,
        method="get",
        download=False,
    ):
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"),
                resp_json,
            )

        for _ in range(self._number_of_retries):
            try:
                r = request_func(
                    url,
                    data=data,
                    headers=headers,
                    verify=verify,
                    params=params,
                    timeout=MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT,
                )
            except Exception as e:
                error_msg = _get_error_msg_from_exception(e, self)
                return RetVal(action_result.set_status(phantom.APP_ERROR, f"Error connecting to server. {error_msg}"), resp_json)

            if r.status_code != 502:
                break
            self.debug_print("Received 502 status code from the server")
            time.sleep(self._retry_wait_time)

        if download:
            if 200 <= r.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, r.text)
            self.debug_print("Error while downloading a file content")
            return RetVal(phantom.APP_ERROR, None)

        return self._process_response(r, action_result)

    def _get_asset_name(self, action_result):
        rest_endpoint = SPLUNK_SOAR_ASSET_INFO_URL.format(url=self.get_phantom_base_url(), asset_id=self._asset_id)

        ret_val, resp_json = self._make_rest_call(action_result, rest_endpoint, False)

        if phantom.is_fail(ret_val):
            return (ret_val, None)

        asset_name = resp_json.get("name")

        if not asset_name:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Asset Name for ID: {self._asset_id} not found",
                None,
            )

        return (phantom.APP_SUCCESS, asset_name)

    def _update_container(self, action_result, container_id, container):
        """
        Update container.

        :param action_result: Action result or BaseConnector object
        :param container_id: container ID
        :param container: container's payload to update
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS with status message
        """
        rest_endpoint = SPLUNK_SOAR_CONTAINER_INFO_URL.format(url=self.get_phantom_base_url(), container_id=container_id)

        try:
            data = json.dumps(container)
        except Exception as e:
            error_msg = _get_error_msg_from_exception(e, self)
            msg = (
                f"json.dumps failed while updating the container: {container_id}. "
                "Possibly a value in the container dictionary is not encoded properly."
                f"Exception: {error_msg}"
            )
            return action_result.set_status(phantom.APP_ERROR, msg)

        ret_val, _ = self._make_rest_call(action_result, rest_endpoint, False, data=data, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _get_phantom_base_url(self, action_result):
        ret_val, resp_json = self._make_rest_call(
            action_result,
            SPLUNK_SOAR_SYS_INFO_URL.format(url=self.get_phantom_base_url()),
            False,
        )

        if phantom.is_fail(ret_val):
            return (ret_val, None)

        phantom_base_url = resp_json.get("base_url").rstrip("/")

        if not phantom_base_url:
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Splunk SOAR Base URL not found in System Settings. Please specify this value in System Settings",
                ),
                None,
            )

        return (phantom.APP_SUCCESS, phantom_base_url)

    def _get_url_to_app_rest(self, action_result=None):
        if not action_result:
            action_result = ActionResult()

        # get the Splunk SOAR ip to redirect to
        ret_val, phantom_base_url = self._get_phantom_base_url(action_result)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        # get the asset name
        ret_val, asset_name = self._get_asset_name(action_result)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        self.save_progress(f"Using Splunk SOAR base URL as: {phantom_base_url}")

        app_json = self.get_app_json()

        app_name = app_json["name"]

        app_dir_name = _get_dir_name_from_app_name(app_name)

        url_to_app_rest = "{}/rest/handler/{}_{}/{}".format(phantom_base_url, app_dir_name, app_json["appid"], asset_name)

        return (phantom.APP_SUCCESS, url_to_app_rest)

    def _make_rest_call_helper(
        self,
        action_result,
        endpoint,
        verify=True,
        headers=None,
        params=None,
        data=None,
        method="get",
        nextLink=None,
        download=False,
        beta=False,
    ):
        if nextLink:
            url = nextLink
        else:
            if not beta:
                url = f"{MSGRAPH_API_URL}/v1.0{endpoint}"
            else:
                url = f"{MSGRAPH_API_URL}/beta{endpoint}"

        if headers is None:
            headers = {}

        headers.update({"Authorization": f"Bearer {self._access_token}", "Accept": "application/json", "Content-Type": "application/json"})

        ret_val, resp_json = self._make_rest_call(action_result, url, verify, headers, params, data, method, download=download)

        # If token is expired, generate a new token
        msg = action_result.get_message()
        if msg and (("token" in msg and "expired" in msg) or any(failure_msg in msg for failure_msg in MSGOFFICE365_AUTH_FAILURE_MSG)):
            self.debug_print("MSGRAPH", f"Error '{msg}' found in API response. Requesting new access token using refresh token")
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({"Authorization": f"Bearer {self._access_token}"})

            ret_val, resp_json = self._make_rest_call(
                action_result,
                url,
                verify,
                headers,
                params,
                data,
                method,
                download=download,
            )

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _sanitize_file_name(self, file_name):
        return re.sub("[,\"']", "", file_name)

    def _add_attachment_to_vault(self, attachment, container_id, file_data):
        fd, tmp_file_path = tempfile.mkstemp(dir=Vault.get_vault_tmp_dir())
        os.close(fd)
        file_mode = "wb" if isinstance(file_data, bytes) else "w"
        with open(tmp_file_path, file_mode) as f:
            f.write(file_data)

        file_name = self._sanitize_file_name(attachment["name"])

        success, msg, vault_id = ph_rules.vault_add(
            container=container_id,
            file_location=tmp_file_path,
            file_name=file_name,
        )
        if not success:
            self.debug_print(f"Error adding file to vault: {msg}")
            return RetVal(phantom.APP_ERROR, None)
        else:
            return RetVal(phantom.APP_SUCCESS, vault_id)

    def _handle_attachment(self, attachment, container_id, artifact_json=None):
        vault_id = None

        try:
            if "contentBytes" in attachment:  # Check whether the attachment contains the data
                file_data = base64.b64decode(attachment.pop("contentBytes"))
                ret_val, vault_id = self._add_attachment_to_vault(attachment, container_id, file_data)
                if phantom.is_fail(ret_val):
                    return phantom.APP_ERROR
            else:
                self.debug_print("No content found in the attachment. Hence, skipping the vault file creation.")

        except Exception as e:
            error_msg = _get_error_msg_from_exception(e, self)
            self.debug_print(f"Error saving file to vault: {error_msg}")
            return phantom.APP_ERROR

        if artifact_json is None:
            attachment["vaultId"] = vault_id
            return phantom.APP_SUCCESS

        artifact_json["name"] = "Vault Artifact"
        artifact_json["label"] = "attachment"
        artifact_json["container_id"] = container_id
        artifact_json["source_data_identifier"] = attachment["id"]

        artifact_cef = {}

        artifact_cef["size"] = attachment["size"]
        artifact_cef["lastModified"] = attachment["lastModifiedDateTime"]
        artifact_cef["filename"] = attachment["name"]
        artifact_cef["mimeType"] = attachment["contentType"]
        if vault_id:
            artifact_cef["vault_id"] = vault_id

        artifact_json["cef"] = artifact_cef

        return phantom.APP_SUCCESS

    def _handle_item_attachment(self, attachment, container_id, endpoint, action_result):
        vault_id = None

        try:
            attach_endpoint = "{}/{}/$value".format(endpoint, attachment["id"])
            ret_val, rfc822_email = self._make_rest_call_helper(action_result, attach_endpoint, download=True)
            if phantom.is_fail(ret_val):
                self.debug_print("Error while downloading the file content, for attachment id: {}".format(attachment["id"]))
                return phantom.APP_ERROR

            attachment["name"] = "{}.eml".format(attachment["name"])

            if rfc822_email:  # Check whether the API returned any data
                ret_val, vault_id = self._add_attachment_to_vault(attachment, container_id, rfc822_email)
                if phantom.is_fail(ret_val):
                    return phantom.APP_ERROR
            else:
                self.debug_print("No content found for the item attachment. Hence, skipping the vault file creation.")

        except Exception as e:
            error_msg = _get_error_msg_from_exception(e, self)
            self.debug_print(f"Error saving file to vault: {error_msg}")
            return phantom.APP_ERROR

        attachment["vaultId"] = vault_id
        return phantom.APP_SUCCESS

    def _create_reference_attachment_artifact(self, container_id, attachment, artifact_json):
        """
        Create reference attachment artifact.

        :param container_id: container ID
        :param attachment: attachment dict
        :param artifact_json: artifact dict to add the data
        :return: phantom.APP_SUCCESS
        """
        artifact_json["name"] = "Reference Attachment Artifact"
        artifact_json["container_id"] = container_id
        artifact_json["source_data_identifier"] = attachment["id"]

        artifact_cef = {}

        artifact_cef["size"] = attachment.get("size")
        artifact_cef["lastModified"] = attachment.get("lastModifiedDateTime")
        artifact_cef["filename"] = attachment.get("name")
        artifact_cef["mimeType"] = attachment.get("contentType")

        artifact_json["cef"] = artifact_cef

        return phantom.APP_SUCCESS

    def _create_email_artifacts(self, container_id, email, artifact_id=None, create_iocs=True):
        """
        Create email artifacts.

        :param container_id: container ID
        :param email: email content
        :param artifact_id: artifact ID
        :return: extracted artifacts list
        """
        artifacts = []

        email_artifact = {}
        email_artifact["label"] = "email"
        email_artifact["name"] = "Email Artifact"
        email_artifact["container_id"] = container_id

        if email.get("id"):
            artifact_id = email["id"]

            # Set email ID contains
            self._process_email._set_email_id_contains(email["id"])
            email_artifact["cef_types"] = {"messageId": self._process_email._email_id_contains}

        email_artifact["source_data_identifier"] = artifact_id

        cef = {}
        email_artifact["cef"] = cef

        for k, v in email.items():
            if v is not None:
                if k == "from":
                    from_obj = v.get("emailAddress", {})
                    cef[k] = from_obj
                    cef["fromEmail"] = from_obj.get("address", "")
                elif k == "toRecipients":
                    cef[k] = v
                    # add first email to To
                    recipients = v
                    if len(recipients):
                        cef["toEmail"] = recipients[0].get("emailAddress", {}).get("address", "")
                elif k == "id":
                    cef["messageId"] = v
                elif k == "internetMessageHeaders":
                    cef["internetMessageHeaders"] = {}
                    if isinstance(v, list):
                        for header in v:
                            key_name = header.get("name")
                            key_value = header.get("value")
                            if key_name and key_value:
                                cef["internetMessageHeaders"][key_name] = key_value
                elif k == "attachments":
                    continue
                else:
                    cef[k] = v

        if cef.get("body", {}).get("content") and (cef.get("body", {}).get("contentType") == "html"):
            html_body = cef["body"]["content"]

            try:
                soup = BeautifulSoup(html_body, "html.parser")
                # Remove the script, style, footer, title and navigation part from the HTML message
                for element in soup(["script", "style", "footer", "title", "nav"]):
                    element.extract()
                body_text = soup.get_text(separator=" ")
                split_lines = body_text.split("\n")
                split_lines = [x.strip() for x in split_lines if x.strip()]
                body_text = "\n".join(split_lines)
                if body_text:
                    cef["bodyText"] = body_text
            except Exception:
                self.debug_print("Cannot parse email body text details")

        if not create_iocs:
            return [email_artifact]

        body = email["body"]["content"]

        ips = []
        self._process_email._get_ips(body, ips)

        for ip in ips:
            ip_artifact = {}
            artifacts.append(ip_artifact)
            ip_artifact["name"] = "IP Artifact"
            ip_artifact["label"] = "artifact"
            ip_artifact["cef"] = ip
            ip_artifact["container_id"] = container_id
            ip_artifact["source_data_identifier"] = artifact_id

        urls = []
        domains = []
        self._process_email._extract_urls_domains(body, urls, domains)

        for url in urls:
            url_artifact = {}
            artifacts.append(url_artifact)
            url_artifact["name"] = "URL Artifact"
            url_artifact["label"] = "artifact"
            url_artifact["cef"] = url
            url_artifact["container_id"] = container_id
            url_artifact["source_data_identifier"] = artifact_id

        for domain in domains:
            domain_artifact = {}
            artifacts.append(domain_artifact)
            domain_artifact["name"] = "Domain Artifact"
            domain_artifact["label"] = "artifact"
            domain_artifact["cef"] = domain
            domain_artifact["container_id"] = container_id
            domain_artifact["source_data_identifier"] = artifact_id

        hashes = []
        self._process_email._extract_hashes(body, hashes)

        for hash in hashes:
            hash_artifact = {}
            artifacts.append(hash_artifact)
            hash_artifact["name"] = "Hash Artifact"
            hash_artifact["label"] = "artifact"
            hash_artifact["cef"] = hash
            hash_artifact["container_id"] = container_id
            hash_artifact["source_data_identifier"] = artifact_id

        artifacts.append(email_artifact)

        return artifacts

    def _extract_attachments(
        self,
        config,
        attach_endpoint,
        artifacts,
        action_result,
        attachments,
        container_id,
        first_time=False,
    ):
        """
        Extract attachments.

        :param config: config dict
        :param attach_endpoint: attachment endpoint
        :param artifacts: artifacts list to append the attachment artifacts
        :param action_result: Action result or BaseConnector object
        :param attachments: attachments list to process
        :param container_id: container ID
        :param first_time: boolean flag to specify if we want to expand the item attachment
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS with status message
        """
        for attachment in attachments:
            if attachment.get("@odata.type") == "#microsoft.graph.itemAttachment":
                # We need to expand the item attachment only once
                if first_time:
                    sub_email_endpoint = attach_endpoint + "/{}?$expand=microsoft.graph.itemattachment/item".format(attachment["id"])
                    ret_val, sub_email_resp = self._make_rest_call_helper(action_result, sub_email_endpoint)
                    if phantom.is_fail(ret_val):
                        return action_result.get_status()
                    sub_email = sub_email_resp.get("item", {})

                else:
                    sub_email = attachment.get("item", {})

                if sub_email:
                    sub_artifacts = self._create_email_artifacts(container_id, sub_email, attachment["id"], create_iocs=False)
                    artifacts += sub_artifacts

                # Use recursive approach to extract the reference attachment
                item_attachments = sub_email.pop("attachments", [])
                if item_attachments:
                    ret_val = self._extract_attachments(
                        config,
                        attach_endpoint,
                        artifacts,
                        action_result,
                        item_attachments,
                        container_id,
                    )
                    if phantom.is_fail(ret_val):
                        self.debug_print("Error while processing nested attachments, for attachment id: {}".format(attachment["id"]))

                if first_time:
                    # Fetch the rfc822 content for the item attachment
                    sub_email_endpoint = "{}/{}/$value".format(attach_endpoint, attachment["id"])
                    attachment["name"] = "{}.eml".format(attachment["name"])
                    ret_val, rfc822_email = self._make_rest_call_helper(action_result, sub_email_endpoint, download=True)
                    if phantom.is_fail(ret_val):
                        self.debug_print("Error while downloading the email content, for attachment id: {}".format(attachment["id"]))

                    if rfc822_email:
                        # Create ProcessEmail Object for email item attachment
                        process_email_obj = ProcessEmail(self, config)
                        process_email_obj._trigger_automation = False

                        ret_val, msg = process_email_obj.process_email(
                            rfc822_email, attachment["id"], epoch=None, container_id=container_id, ingest_email=False
                        )

                        if phantom.is_fail(ret_val):
                            self.debug_print("Error while processing the email content, for attachment id: {}".format(attachment["id"]))

                        if config.get("ingest_eml", False):
                            # Add eml file into the vault if ingest_email is checked
                            ret_val, vault_id = self._add_attachment_to_vault(attachment, container_id, rfc822_email)
                            if phantom.is_fail(ret_val):
                                self.debug_print("Could not process item attachment. See logs for details")
                            else:
                                # If success, create vault artifact
                                artifact_json = {
                                    "name": "Vault Artifact",
                                    "label": "attachment",
                                    "container_id": container_id,
                                    "source_data_identifier": attachment["id"],
                                }

                                artifact_cef = {
                                    "size": attachment["size"],
                                    "lastModified": attachment["lastModifiedDateTime"],
                                    "filename": attachment["name"],
                                    "mimeType": attachment["contentType"],
                                }
                                if vault_id:
                                    artifact_cef["vault_id"] = vault_id
                                artifact_json["cef"] = artifact_cef
                                artifacts.append(artifact_json)

                    else:
                        self.debug_print("No content found for the item attachment. Hence, skipping the email file processing.")

            elif attachment.get("@odata.type") == "#microsoft.graph.referenceAttachment":
                attach_artifact = {}
                artifacts.append(attach_artifact)
                self._create_reference_attachment_artifact(container_id, attachment, attach_artifact)

            elif attachment.get("name", "").endswith(".eml"):
                if "contentBytes" in attachment:
                    try:
                        rfc822_email = base64.b64decode(attachment["contentBytes"])
                        rfc822_email = UnicodeDammit(rfc822_email).unicode_markup
                    except Exception as e:
                        error_msg = _get_error_msg_from_exception(e, self)
                        self.debug_print(f"Unable to decode Email Mime Content. {error_msg}")
                        return action_result.set_status(phantom.APP_ERROR, "Unable to decode Email Mime Content")

                    # Create ProcessEmail Object for email file attachment
                    process_email_obj = ProcessEmail(self, config)
                    process_email_obj._trigger_automation = False

                    ret_val, msg = process_email_obj.process_email(rfc822_email, attachment["id"], epoch=None, container_id=container_id)

                    if phantom.is_fail(ret_val):
                        return action_result.set_status(phantom.APP_ERROR, msg)
                else:
                    self.debug_print("No content found in the .eml file attachment. Hence, skipping the email file processing.")

            elif first_time:
                attach_artifact = {}
                artifacts.append(attach_artifact)
                if not self._handle_attachment(attachment, container_id, artifact_json=attach_artifact):
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        "Could not process attachment. See logs for details.",
                    )

        return phantom.APP_SUCCESS

    def _process_email_data(self, config, action_result, endpoint, email):
        """
        Process email data.

        :param config: config dict
        :param action_result: Action result or BaseConnector object
        :param endpoint: endpoint for making REST calls
        :param emails: Emails to process
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS with status message
        """
        container = {}

        container["name"] = email["subject"] if email["subject"] else email["id"]
        container_description = MSGOFFICE365_CONTAINER_DESCRIPTION.format(last_modified_time=email["lastModifiedDateTime"])
        container["description"] = container_description
        container["source_data_identifier"] = email["id"]
        container["data"] = {"raw_email": email}

        ret_val, msg, container_id = self.save_container(container)

        if phantom.is_fail(ret_val) or not container_id:
            return action_result.set_status(phantom.APP_ERROR, msg)

        if MSGOFFICE365_DUPLICATE_CONTAINER_FOUND_MSG in msg.lower():
            self.debug_print("Duplicate container found")
            self._duplicate_count += 1

            # Prevent further processing if the email is not modified
            ret_val, container_info, status_code = self.get_container_info(container_id=container_id)
            if phantom.is_fail(ret_val):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Status Code: {status_code}. Error occurred while fetching the container info for container ID: {container_id}",
                )

            if container_info.get("description", "") == container_description:
                msg = "Email ID: {} has not been modified. Hence, skipping the artifact ingestion.".format(email["id"])
                self.debug_print(msg)
                return action_result.set_status(phantom.APP_SUCCESS, msg)
            else:
                # Update the container's description and continue
                self.debug_print("Updating container's description")
                ret_val = self._update_container(action_result, container_id, container)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()

        self.debug_print("Creating email artifacts")
        email_artifacts = self._create_email_artifacts(container_id, email)
        attachment_artifacts = []

        if config.get("extract_eml", True):
            subject = email.get("subject")
            email_message = {
                "id": email["id"],
                "name": subject if subject else "email_message_{}".format(email["id"]),
            }
            if not self._handle_item_attachment(
                email_message,
                container_id,
                "/users/{}/messages".format(config.get("email_address")),
                action_result,
            ):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Could not download the email. See logs for details",
                )
            email["vaultId"] = email_message["vaultId"]

            artifact_json = {
                "name": "Vault Artifact",
                "label": "Email Attachment",
                "container_id": container_id,
                "source_data_identifier": email["id"],
            }

            artifact_cef = {
                "filename": "{}.eml".format(email_message["name"]),
            }

            if email_message["vaultId"]:
                artifact_cef.update({"vaultId": email_message["vaultId"]})
            artifact_json["cef"] = artifact_cef
            attachment_artifacts.append(artifact_json)

        if email["hasAttachments"] and config.get("extract_attachments", False):
            attach_endpoint = endpoint + "/{}/attachments".format(email["id"])
            ret_val, attach_resp = self._make_rest_call_helper(action_result, attach_endpoint)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            ret_val = self._extract_attachments(
                config,
                attach_endpoint,
                attachment_artifacts,
                action_result,
                attach_resp.get("value", []),
                container_id,
                first_time=True,
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        artifacts = attachment_artifacts + email_artifacts
        ret_val, msg, container_id = self.save_artifacts(artifacts)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, msg)

        return phantom.APP_SUCCESS

    def _process_email_details(
        self, action_result, email, email_address, endpoint, extract_headers=False, download_attachments=False, download_email=False
    ):
        """
        Process email details including headers, attachments and email downloads.

        :param action_result: Action result object for tracking status
        :param email: Email object to process
        :param email_address: Email address of the mailbox
        :param endpoint: Base endpoint for API calls
        :param extract_headers: Whether to extract email headers (default: False)
        :param download_attachments: Whether to download attachments (default: False)
        :param download_email: Whether to download the email as EML (default: False)
        :return: Updated email object with additional details including:
                - internetMessageHeaders: Flattened email headers if extract_headers=True
                - attachments: List of processed attachments if download_attachments=True
                - vaultId: Vault ID of downloaded EML file if download_email=True
        """
        if extract_headers:
            header_endpoint = endpoint + "?$select=internetMessageHeaders"
            ret_val, header_response = self._make_rest_call_helper(action_result, header_endpoint)

            if phantom.is_fail(ret_val):
                return action_result.get_status()
            # For Drafts there might not be any internetMessageHeaders,
            # so we have to use get() fetching instead of directly fetching from dictionary
            email["internetMessageHeaders"] = header_response.get("internetMessageHeaders")

        if download_attachments and email.get("hasAttachments"):
            endpoint += "/attachments"
            attachment_endpoint = f"{endpoint}?$expand=microsoft.graph.itemattachment/item"
            ret_val, attach_resp = self._make_rest_call_helper(action_result, attachment_endpoint)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            for attachment in attach_resp.get("value", []):
                # If it is fileAttachment, then we have to ingest it
                if attachment.get("@odata.type") == "#microsoft.graph.fileAttachment":
                    if not self._handle_attachment(attachment, self.get_container_id()):
                        return action_result.set_status(
                            phantom.APP_ERROR,
                            "Could not process attachment. See logs for details",
                        )
                elif attachment.get("@odata.type") == "#microsoft.graph.itemAttachment":
                    if not self._handle_item_attachment(attachment, self.get_container_id(), endpoint, action_result):
                        return action_result.set_status(
                            phantom.APP_ERROR,
                            "Could not process item attachment. See logs for details",
                        )

            email["attachments"] = attach_resp["value"]

        if email.get("@odata.type") in [
            "#microsoft.graph.eventMessage",
            "#microsoft.graph.eventMessageRequest",
            "#microsoft.graph.eventMessageResponse",
        ]:
            event_endpoint = f"{endpoint}/?$expand=Microsoft.Graph.EventMessage/Event"
            ret_val, event_resp = self._make_rest_call_helper(action_result, event_endpoint)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            email["event"] = event_resp["event"]

        if "internetMessageHeaders" in email:
            email["internetMessageHeaders"] = self._flatten_headers(email["internetMessageHeaders"])

        # If the response has attachments, update every attachment data with its type
        # 'attachmentType' key - indicates type of attachment
        # and if an email has any itemAttachment, then also add itemType in the response
        # 'itemType' key - indicates type of itemAttachment
        if email.get("attachments", []):
            for attachment in email["attachments"]:
                attachment_type = attachment.get("@odata.type", "")
                attachment["attachmentType"] = attachment_type
                if attachment_type == "#microsoft.graph.itemAttachment":
                    attachment["itemType"] = attachment.get("item", {}).get("@odata.type", "")

        if download_email:
            subject = email.get("subject")
            email_message = {
                "id": email["id"],
                "name": subject if subject else "email_message_{}".format(email["id"]),
            }
            if not self._handle_item_attachment(
                email_message,
                self.get_container_id(),
                f"/users/{email_address}/messages",
                action_result,
            ):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Could not download the email. See logs for details",
                )
            email["vaultId"] = email_message["vaultId"]

        return email

    def _remove_tokens(self, action_result):
        # checks whether the message includes any of the known error codes

        if len(list(filter(lambda x: x in action_result.get_message(), MSGOFFICE365_ASSET_PARAM_CHECK_LIST_ERROR))) > 0:
            if not self._admin_access:
                if self._state.get("non_admin_auth", {}).get("access_token"):
                    self._state["non_admin_auth"].pop("access_token")
                if self._state.get("non_admin_auth", {}).get("refresh_token"):
                    self._state["non_admin_auth"].pop("refresh_token")
            else:
                if self._state.get("admin_auth", {}).get("access_token"):
                    self._state["admin_auth"].pop("access_token")

    def _handle_test_connectivity(self, param):
        """Function that handles the test connectivity action, it is much simpler than other action handlers."""

        action_result = self.add_action_result(ActionResult(param))

        # Get Consent in OAuth Authentication and it's requires Client Secret (Scenario - Automatic)
        if self._auth_type != "cba" and self._client_secret and not (self._admin_access and self._admin_consent):
            ret_val = self._get_consent(action_result)
            if phantom.is_fail(ret_val):
                if self._auth_type == "oauth":
                    return action_result.get_status()
                else:
                    self._auth_type = "cba"
                    self.save_progress("Failed to obtain consent, switching to Certificate Based Authentication")
                    if not (self._thumbprint and self._certificate_private_key):
                        return action_result.set_status(
                            phantom.APP_ERROR,
                            "Tried switching to Certificate Based Authentication, but the necessary CBA configuraiton parameters are not set.",
                        )

        self.save_progress("Getting the token")
        ret_val = self._get_token(action_result)

        if phantom.is_fail(ret_val):
            self._remove_tokens(action_result)
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        params = {"$top": "1"}
        message_failed = ""

        # Application permissions are not supported when using the /me endpoint. (Scenario - CBA using /users)
        if self._admin_access or self._state["auth_type"] == "cba":
            message_failed = "API to fetch details of all the users failed"
            self.save_progress("Getting info about all users to verify token")
            ret_val, response = self._make_rest_call_helper(action_result, "/users", params=params)
        else:
            message_failed = "API to get user details failed"
            self.save_progress("Getting info about a single user to verify token")
            ret_val, response = self._make_rest_call_helper(action_result, "/me", params=params)

        if phantom.is_fail(ret_val):
            self.save_progress(message_failed)
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR)

        value = response.get("value")

        if value:
            self.save_progress("Got user info")

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_copy_email(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param["email_address"]
        folder = param["folder"]
        message_id = param["id"]
        endpoint = f"/users/{email_addr}"

        endpoint += f"/messages/{message_id}/copy"

        body = {"DestinationId": folder}

        if param.get("get_folder_id", True):
            try:
                dir_id, error, _ = self._get_folder_id(action_result, folder, email_addr)
            except ReturnException as e:
                self._dump_error_log(e)
                return action_result.get_status()

            if dir_id:
                body["DestinationId"] = dir_id
            else:
                self.save_progress(error)
                return action_result.set_status(phantom.APP_ERROR, error)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, data=json.dumps(body), method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully copied email")

    def _handle_move_email(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param["email_address"]
        folder = param["folder"]
        message_id = param["id"]
        endpoint = f"/users/{email_addr}"

        endpoint += f"/messages/{message_id}/move"

        body = {"DestinationId": folder}
        if param.get("get_folder_id", True):
            try:
                dir_id, error, _ = self._get_folder_id(action_result, folder, email_addr)

            except ReturnException as e:
                self._dump_error_log(e)
                return action_result.get_status()

            if dir_id:
                body["DestinationId"] = dir_id

            else:
                self.save_progress(error)
                return action_result.set_status(phantom.APP_ERROR, error)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, data=json.dumps(body), method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully moved email")

    def _handle_delete_email(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param["email_address"]
        message_id = param["id"]
        endpoint = f"/users/{email_addr}"

        endpoint += f"/messages/{message_id}"

        ret_val, _ = self._make_rest_call_helper(action_result, endpoint, method="delete")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted email")

    def _handle_delete_event(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param["email_address"]
        message_id = param["id"]
        send_decline_response = param.get("send_decline_response")
        endpoint = f"/users/{email_addr}/events/{message_id}"
        method = "delete"
        data = None
        if send_decline_response:
            method = "post"
            endpoint += "/decline"
            data = json.dumps({"sendResponse": True})

        ret_val, _ = self._make_rest_call_helper(action_result, endpoint, method=method, data=data)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted event")

    def _handle_oof_check(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param["user_id"]

        endpoint = f"/users/{user_id}/mailboxSettings/automaticRepliesSetting"

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, method="get")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        action_result.update_summary({"events_matched": action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved out of office status")

    def _handle_list_events(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param.get("user_id") if param.get("user_id") else None
        group_id = param.get("group_id") if param.get("group_id") else None
        query = param.get("filter") if param.get("filter") else None
        limit = param.get("limit")

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if user_id is None and group_id is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Either a "user_id" or "group_id" must be supplied to the "list_events" action',
            )

        if user_id and group_id and user_id != "" and group_id != "":
            return action_result.set_status(
                phantom.APP_ERROR,
                'Either a user_id or group_id can be supplied to the "list_events" action - not both',
            )

        endpoint = ""

        if user_id:
            endpoint = f"/users/{user_id}/calendar/events"
        else:
            endpoint = f"/groups/{group_id}/calendar/events"

        if query:
            endpoint = f"{endpoint}?{query}"

        ret_val, events = self._paginator(action_result, endpoint, limit)

        if phantom.is_fail(ret_val):
            msg = action_result.get_message()
            if "$top" in msg or "$top/top" in msg:
                msg += "The '$top' parameter is already used internally to handle pagination logic. "
                msg += "If you want to restrict results in terms of number of output results, you can use the 'limit' parameter."
                return action_result.set_status(phantom.APP_ERROR, msg)
            return action_result.get_status()

        if not events:
            # No events found is a valid scenario that there can be 0 events returned
            # even if the API call is a success for the correct given inputs and hence, returning APP_SUCCESS.
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for event in events:
            attendees = [attendee.get("emailAddress", {}).get("name") for attendee in event.get("attendees", [])]
            event["attendee_list"] = ", ".join(attendees)
            action_result.add_data(event)

        num_events = len(events)
        action_result.update_summary({"events_matched": action_result.get_data_size()})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully retrieved {} event{}".format(num_events, "" if num_events == 1 else "s"),
        )

    def _handle_list_groups(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get("limit")

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        query = param.get("filter") if param.get("filter") else None

        endpoint = "/groups"

        ret_val, groups = self._paginator(action_result, endpoint, limit, query=query)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not groups:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for group in groups:
            action_result.add_data(group)

        num_groups = len(groups)
        action_result.update_summary({"total_groups_returned": num_groups})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully retrieved {} group{}".format(num_groups, "" if num_groups == 1 else "s"),
        )

    def _handle_list_group_members(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get("limit")
        query = None
        is_advance_query = False

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        method = param.get("method", "Group ID")
        group_id = identificator = param["identificator"]
        if param.get("filter"):
            query = param.get("filter")
            is_advance_query = True

        if method.lower() not in ("group id", "group e-mail"):
            return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_INVALID_METHOD)

        if method.lower() == "group e-mail":
            if not util.is_email(identificator):
                return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_INVALID_EMAIL)

            name_filtering = f"mail eq '{identificator}'"
            ret_val, group = self._paginator(action_result, "/groups", limit, query=name_filtering)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not group:
                return action_result.set_status(
                    phantom.APP_ERROR, f"There is no such {identificator} group name, Please check the correct spelling or existence"
                )
            group_id = group[0]["id"]

        transitive_members = param.get("get_transitive_members", True)
        endpoint = f"/groups/{group_id}/members"
        if transitive_members:
            endpoint = f"/groups/{group_id}/transitiveMembers"

        ret_val, members = self._paginator(action_result, endpoint, limit, query=query, is_advance_query=is_advance_query)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not members:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for member in members:
            action_result.add_data(member)

        num_members = len(members)
        action_result.update_summary({"total_members_returned": num_members})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully retrieved {} group member{}".format(num_members, "" if num_members == 1 else "s"),
        )

    def _handle_list_users(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get("limit")

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        query = param.get("filter") if param.get("filter") else None

        endpoint = "/users"

        ret_val, users = self._paginator(action_result, endpoint, limit, query=query)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not users:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for user in users:
            action_result.add_data(user)

        num_users = len(users)
        action_result.update_summary({"total_users_returned": num_users})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully retrieved {} user{}".format(num_users, "" if num_users == 1 else "s"),
        )

    def _handle_list_rules(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param["user_id"]

        endpoint = f"/users/{user_id}/mailFolders/inbox/messageRules"

        ret_val, rules = self._paginator(action_result, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not rules:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for rule in rules:
            action_result.add_data(rule)

        num_rules = len(rules)
        action_result.update_summary({"total_rules_returned": num_rules})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully retrieved {} rule{}".format(num_rules, "" if num_rules == 1 else "s"),
        )

    def flatten_json(self, y):
        out = {}

        def flatten(x, name=""):
            if type(x) is dict:
                for a in x:
                    flatten(x[a], name + a + "_")
            elif type(x) is list:
                i = 0
                for a in x:
                    flatten(a, name + str(i) + "_")
                    i += 1
            else:
                out[name[:-1]] = x

        flatten(y)
        return out

    def _handle_get_rule(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param["user_id"]
        rule_id = param["rule_id"]

        endpoint = f"/users/{user_id}/mailFolders/inbox/messageRules/{rule_id}"

        ret_val, rule = self._make_rest_call_helper(action_result, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not rule:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        rule = self.flatten_json(rule)
        self.debug_print(rule)
        action_result.add_data(rule)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved specified inbox rule")

    def _handle_list_folders(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_folder = list()
        user_id = param["user_id"]
        folder_id = param.get("folder_id")

        if not folder_id:
            # fetching root level folders
            ret_val, root_folders = self._fetch_root_folders(action_result, user_id)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # adding root folders to main list of folders
            list_folder.extend(root_folders)

            # checking for child folder if have, add it in list of folders
            for root_folder in root_folders:
                if root_folder.get("childFolderCount", 0) == 0:
                    continue
                else:
                    ret_val = self._list_child_folders(
                        action_result,
                        list_folder,
                        user_id=user_id,
                        parent_folder=root_folder,
                    )

                    if phantom.is_fail(ret_val):
                        return action_result.get_status()
        else:
            ret_val = self._list_child_folders(action_result, list_folder, user_id=user_id, folder_id=folder_id)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        for folder in list_folder:
            action_result.add_data(folder)

        num_folders = len(list_folder)
        action_result.update_summary({"total_folders_returned": num_folders})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully retrieved {} mail folder{}".format(num_folders, "" if num_folders == 1 else "s"),
        )

    def _fetch_root_folders(self, action_result, user_id):
        endpoint = f"/users/{user_id}/mailFolders"

        ret_val, folders = self._paginator(action_result, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        if not folders:
            return (
                action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND),
                None,
            )

        return phantom.APP_SUCCESS, folders

    def _list_child_folders(self, action_result, list_folder, user_id, parent_folder=None, folder_id=None):
        # fetching root level folders
        if not folder_id:
            ret_val, child_folders = self._fetch_child_folders(action_result, user_id, parent_folder["id"])
        else:
            ret_val, child_folders = self._fetch_child_folders(action_result, user_id, folder_id)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # checking for child folder if have, add it in list of folders
        for child_folder in child_folders:
            if child_folder.get("childFolderCount", 0) == 0:
                list_folder.append(child_folder)
            else:
                ret_val = self._list_child_folders(
                    action_result,
                    list_folder,
                    user_id=user_id,
                    parent_folder=child_folder,
                )

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                list_folder.append(child_folder)

        return phantom.APP_SUCCESS

    def _fetch_child_folders(self, action_result, user_id, folder_id):
        endpoint = f"/users/{user_id}/mailFolders/{folder_id}/childFolders"

        ret_val, folders = self._paginator(action_result, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, folders

    def _flatten_headers(self, headers):
        new_headers = {}
        if not headers:
            return new_headers

        for field in headers:
            if field["name"] == "Received":
                if "Received" not in new_headers:
                    new_headers["Received"] = []
                new_headers["Received"].append(field["value"])
                continue

            new_headers[field["name"]] = field["value"]

        return new_headers

    def _handle_get_email(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param["email_address"]
        message_id = param["id"]
        endpoint = f"/users/{email_addr}"

        endpoint += f"/messages/{message_id}"

        ret_val, response = self._make_rest_call_helper(action_result, endpoint)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        response = self._process_email_details(
            action_result,
            response,
            email_addr,
            endpoint,
            extract_headers=param.get("extract_headers"),
            download_attachments=param.get("download_attachments", False),
            download_email=param.get("download_email", False),
        )

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched email")

    def _handle_get_email_properties(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param["email_address"]
        message_id = param["id"]
        endpoint = f"/users/{email_addr}"

        endpoint += f"/messages/{message_id}"

        select_list = []
        if param.get("get_headers"):
            select_list.append("internetMessageHeaders")
        if param.get("get_body"):
            select_list.append("body")
        if param.get("get_unique_body"):
            select_list.append("uniqueBody")
        if param.get("get_sender"):
            select_list.append("sender")
        if "properties_list" in param:
            properties_list = param["properties_list"]
            properties_list = [property.strip() for property in properties_list.strip().split(",") if property.strip()]
            select_list += properties_list

        if select_list:
            endpoint += "?$select={}".format(",".join(select_list))

        ret_val, response = self._make_rest_call_helper(action_result, endpoint)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if "internetMessageHeaders" in response:
            response["internetMessageHeaders"] = self._flatten_headers(response["internetMessageHeaders"])

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched email")

    def _manage_data_duplication(self, emails, total_ingested, limit, max_emails):
        """
        This function handles the duplicate emails we get during the ingestion process.

        :param emails: Processed emails
        :param total_ingested: Total ingested emails till now
        :param limit: Current pagination limit
        :param max_emails: Max emails to ingest
        :return: limit: next cycle pagination limit, total_ingested: Total ingested emails till now
        """
        total_ingested_current_cycle = limit - self._duplicate_count
        total_ingested += total_ingested_current_cycle

        remaining_count = max_emails - total_ingested
        if remaining_count <= 0:
            return 0, total_ingested

        expected_duplicate_count_in_next_cycle = 0
        last_modified_time = emails[-1]["lastModifiedDateTime"]

        # Calculate the duplicate emails count we can get in the next cycle
        for email in reversed(emails):
            if email["lastModifiedDateTime"] != last_modified_time:
                break
            expected_duplicate_count_in_next_cycle += 1

        limit = expected_duplicate_count_in_next_cycle + remaining_count
        return limit, total_ingested

    def _handle_on_poll(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        ingest_manner = config.get("ingest_manner", "oldest first")

        start_time = ""
        if self.is_poll_now():
            max_emails = param[phantom.APP_JSON_CONTAINER_COUNT]
        elif self._state.get("first_run", True):
            # Integer validation for 'first_run_max_emails' config parameter
            ret_val, max_emails = _validate_integer(
                action_result,
                config.get("first_run_max_emails", 1000),
                "'Maximum Containers for scheduled polling first time' config",
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        else:
            # Integer validation for 'max_containers' config parameter
            ret_val, max_emails = _validate_integer(
                action_result,
                config.get("max_containers", 100),
                "'Maximum Containers for scheduled polling' config",
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            start_time = self._state["last_time"]

        if not config.get("email_address"):
            return action_result.set_status(phantom.APP_ERROR, "Email Address to ingest must be supplied in asset!")
        elif not config.get("folder"):
            return action_result.set_status(phantom.APP_ERROR, "Folder to ingest from must be supplied in asset!")

        endpoint = "/users/{}".format(config.get("email_address"))

        if "folder" in config:
            folder = config.get("folder", "")
            if config.get("get_folder_id", True):
                try:
                    dir_id, error, _ = self._get_folder_id(action_result, folder, config.get("email_address"))
                except ReturnException as e:
                    self._dump_error_log(e)

                    return action_result.get_status()
                if dir_id:
                    folder = dir_id
                else:
                    self.save_progress(error)
                    return action_result.set_status(phantom.APP_ERROR, error)
            endpoint += f"/mailFolders/{folder}"

        endpoint += "/messages"
        order = "asc" if ingest_manner == "oldest first" else "desc"

        params = {"$orderBy": f"lastModifiedDateTime {order}"}

        params["$select"] = ",".join(MSGOFFICE365_SELECT_PARAMETER_LIST)

        if start_time:
            params["$filter"] = f"lastModifiedDateTime ge {start_time}"

        cur_limit = max_emails
        total_ingested = 0

        # If the ingestion manner is set for the latest emails, then the 0th index email is the latest
        # in the list returned, else the last email is the latest. This will be used to store the
        # last modified time in the state file
        email_index = 0 if ingest_manner == "latest first" else -1

        while True:
            self._duplicate_count = 0
            ret_val, emails = self._paginator(action_result, endpoint, limit=cur_limit, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not emails:
                return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

            failed_email_ids = 0
            total_emails = len(emails)

            self.save_progress(f"Total emails fetched: {total_emails}")
            if self.is_poll_now():
                self.save_progress("Ingesting all possible artifacts (ignoring maximum artifacts value) for POLL NOW")

            for index, email in enumerate(emails):
                try:
                    self.send_progress("Processing email # {} with ID ending in: {}".format(index + 1, email["id"][-10:]))
                    ret_val = self._process_email_data(config, action_result, endpoint, email)
                    if phantom.is_fail(ret_val):
                        failed_email_ids += 1

                        self.debug_print("Error occurred while processing email ID: {}. {}".format(email.get("id"), action_result.get_message()))
                except Exception as e:
                    failed_email_ids += 1
                    error_msg = _get_error_msg_from_exception(e, self)
                    self.debug_print(f"Exception occurred while processing email ID: {email.get('id')}. {error_msg}")

            if failed_email_ids == total_emails:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Error occurred while processing all the email IDs",
                )

            if not self.is_poll_now():
                last_time = datetime.strptime(emails[email_index]["lastModifiedDateTime"], O365_TIME_FORMAT).strftime(O365_TIME_FORMAT)
                self._state["last_time"] = last_time
                self.save_state(deepcopy(self._state))

                # Setting filter for next cycle
                params["$filter"] = f"lastModifiedDateTime ge {last_time}"

                # Duplication logic should only work for the oldest first order and if we have more data on the server.
                if total_emails >= cur_limit and email_index == -1:
                    cur_limit, total_ingested = self._manage_data_duplication(emails, total_ingested, cur_limit, max_emails)
                    if not cur_limit:
                        break
                else:
                    break
            else:
                break

        # Update the 'first_run' value only if the ingestion gets successfully completed
        if not self.is_poll_now() and self._state.get("first_run", True):
            self._state["first_run"] = False

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_range(self, email_range, action_result):
        try:
            mini, maxi = (int(x) for x in email_range.split("-"))
        except Exception:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to parse the range. Please specify the range as min_offset-max_offset",
            )

        if mini < 0 or maxi < 0:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Invalid min or max offset value specified in range",
            )

        if mini > maxi:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Invalid range value, min_offset greater than max_offset",
            )

        if maxi > MAX_END_OFFSET_VAL:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Invalid range value. The max_offset value cannot be greater than {MAX_END_OFFSET_VAL}",
            )

        return phantom.APP_SUCCESS

    def _handle_generate_token(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._get_token(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state["admin_consent"] = True

        return action_result.set_status(phantom.APP_SUCCESS, "Token generated")

    def _handle_run_query(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get("limit")
        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # user
        email_addr = param["email_address"]
        endpoint = f"/users/{email_addr}"
        query = ""
        params = dict()

        if "internet_message_id" in param:
            params = {"$filter": "internetMessageId eq '{}'".format(param["internet_message_id"])}

        elif "query" in param:
            query = "?{}".format(param["query"])

        else:
            # search params
            search_query = ""
            if "subject" in param:
                search_query += "subject:{} ".format(param["subject"])

            if "body" in param:
                search_query += "body:{} ".format(param["body"])

            if "sender" in param:
                search_query += "from:{} ".format(param["sender"])

            if search_query:
                params["$search"] = f'"{search_query[:-1]}"'

        folder_ids = []
        # searches through well known folders
        if param.get("search_well_known_folders", False):
            endpoint += "/mailFolders"
            for folder in MSGOFFICE365_WELL_KNOWN_FOLDERS_FILTER:
                folder_ids.append(folder)

            endpoint += "/{folder_id}"

        # folder
        elif "folder" in param:
            folder = param["folder"]

            if param.get("get_folder_id", True):
                try:
                    dir_id, error, _ = self._get_folder_id(action_result, folder, email_addr)
                except ReturnException as e:
                    self._dump_error_log(e)

                    return action_result.get_status()
                if dir_id:
                    folder = dir_id
                else:
                    self.save_progress(error)
                    return action_result.set_status(phantom.APP_ERROR, error)
            folder_ids.append(folder)
            endpoint += "/mailFolders/{folder_id}"

        # that should be enough to create the endpoint
        endpoint += "/messages"

        if folder_ids:
            messages = []
            ret_val = False
            for folder_id in folder_ids:
                folder_ret_val, folder_messages = self._paginator(
                    action_result,
                    endpoint.format(folder_id=folder_id) + query,
                    limit,
                    params=params,
                )

                if phantom.is_fail(folder_ret_val):
                    continue

                ret_val = True
                messages.extend(folder_messages)

        else:
            ret_val, messages = self._paginator(action_result, endpoint, limit, params=params)

        if phantom.is_fail(ret_val):
            msg = action_result.get_message()
            if "$top" in msg or "$top/top" in msg:
                msg += "The '$top' parameter is already used internally to handle pagination logic. "
                msg += "If you want to restrict results in terms of number of output results, you can use the 'limit' parameter."
                return action_result.set_status(phantom.APP_ERROR, msg)
            return action_result.get_status()

        if not messages:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        action_result.update_data(messages)
        action_result.update_summary({"emails_matched": action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_folder_id(self, action_result, folder, email):
        # hindsight is always 20-20, set the folder path separator to be '/', thinking folder names allow '\' as a char.
        # turns out even '/' is supported by office365, so let the action escape the '/' char if it's part of the folder name
        folder_path = folder.replace("\\/", self._REPLACE_CONST)
        folder_names = folder_path.split("/")
        for i, folder_name in enumerate(folder_names):
            folder_names[i] = folder_name.replace(self._REPLACE_CONST, "/").strip()

        # remove empty elements
        path = list(filter(None, folder_names))

        ret = list()
        try:
            dir_id = self._get_folder(action_result, path[0], email)
        except ReturnException as e:
            self._dump_error_log(e)
            return None, f"Error occurred while fetching folder {path[0]}. {e}", None

        if not dir_id:
            return None, f"Error: folder not found; {path[0]}", ret

        ret.append({"path": path[0], "folder": path[0], "folder_id": dir_id})

        try:
            for i, subf in enumerate(path[1:]):
                subpath = "/".join(path[0 : i + 2])
                parent_id = dir_id
                dir_id = self._get_child_folder(action_result, subf, parent_id, email)

                if not dir_id:
                    return (
                        None,
                        f"Error: child folder not found; {subpath}",
                        ret,
                    )

                ret.append({"path": subpath, "folder": subf, "folder_id": dir_id})
        except ReturnException as e:
            self._dump_error_log(e)
            return None, action_result.get_message(), None

        return dir_id, None, ret

    def _get_folder(self, action_result, folder, email):
        params = {}
        params["$filter"] = f"displayName eq '{folder}'"
        endpoint = f"/users/{email}/mailFolders"

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params)

        if phantom.is_fail(ret_val):
            raise ReturnException(action_result.get_message())

        value = response.get("value", [])
        if len(value) > 0:
            self._currentdir = value[0]
            return value[0]["id"]

        return None

    def _get_child_folder(self, action_result, folder, parent_id, email):
        params = {}
        params["$filter"] = f"displayName eq '{folder}'"
        endpoint = f"/users/{email}/mailFolders/{parent_id}/childFolders"

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params)

        if phantom.is_fail(ret_val):
            raise ReturnException()

        value = response.get("value", [])
        if len(value) > 0:
            self._currentdir = value[0]
            return value[0]["id"]

        return None

    def _new_folder(self, action_result, folder, email):
        data = json.dumps({"displayName": folder})
        endpoint = f"/users/{email}/mailFolders"

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, data=data, method="post")
        if phantom.is_fail(ret_val):
            raise ReturnException()

        if response.get("id", False):
            self._currentdir = response
            self.save_progress(f"Success({folder}): created folder in mailbox")
            return response["id"]

        msg = f"Error({folder}): unable to create folder in mailbox"
        self.save_progress(msg)
        action_result.set_status(phantom.APP_ERROR, msg)
        raise ReturnException()

    def _new_child_folder(self, action_result, folder, parent_id, email, pathsofar):
        data = json.dumps({"displayName": folder})
        endpoint = f"/users/{email}/mailFolders/{parent_id}/childFolders"

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, data=data, method="post")
        if phantom.is_fail(ret_val):
            raise ReturnException()

        if response.get("id", False):
            self._currentdir = response
            self.save_progress(f"Success({folder}): created child folder in folder {pathsofar}")
            return response["id"]

        msg = f"Error({folder}): unable to create child folder in folder {pathsofar}"
        self.save_progress(msg)
        action_result.set_status(phantom.APP_ERROR, msg)
        raise ReturnException()

    def _handle_create_folder(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email = param["email_address"]
        folder = param["folder"]

        minusp = param.get("all_subdirs", False)

        # hindsight is always 20-20, set the folder path separator to be '/', thinking folder names allow '\' as a char.
        # turns out even '/' is supported by office365, so let the action escape the '/' char if it's part of the folder name
        folder_path = folder.replace("\\/", self._REPLACE_CONST)
        folder_names = folder_path.split("/")
        for i, folder_name in enumerate(folder_names):
            folder_names[i] = folder_name.replace(self._REPLACE_CONST, "/").strip()

        # remove empty elements
        path = list(filter(None, folder_names))

        if len(path) == 0:
            msg = "Error: Invalid folder path"
            self.save_progress(msg)
            return action_result.set_status(phantom.APP_ERROR, msg)

        try:
            dir_id = self._get_folder(action_result, path[0], email)

            # only one, create as "Folder" in mailbox
            if len(path) == 1:
                if dir_id:
                    msg = f"Error({path[0]}): folder already exists in mailbox"
                    self.save_progress(msg)
                    return action_result.set_status(phantom.APP_ERROR, msg)

                self._new_folder(action_result, path[0], email)
                action_result.add_data(self._currentdir)

            # walk the path elements, creating each as needed
            else:
                pathsofar = ""

                # first deal with the initial Folder
                if not dir_id:
                    if minusp:
                        dir_id = self._new_folder(action_result, path[0], email)
                        action_result.add_data(self._currentdir)

                    else:
                        msg = f"Error({path[0]}): folder doesn't exists in mailbox"
                        self.save_progress(msg)
                        return action_result.set_status(phantom.APP_ERROR, msg)

                pathsofar += "/" + path[0]
                parent_id = dir_id

                # next extract the final childFolder
                final = path[-1]
                path = path[1:-1]

                # next all the childFolders in between
                for subf in path:
                    dir_id = self._get_child_folder(action_result, subf, parent_id, email)

                    if not dir_id:
                        if minusp:
                            dir_id = self._new_child_folder(action_result, subf, parent_id, email, pathsofar)
                            action_result.add_data(self._currentdir)

                        else:
                            msg = f"Error({subf}): child folder doesn't exists in folder {pathsofar}"
                            self.save_progress(msg)
                            return action_result.set_status(phantom.APP_ERROR, msg)

                    pathsofar += "/" + subf
                    parent_id = dir_id

                # finally, the actual folder
                dir_id = self._get_child_folder(action_result, final, parent_id, email)
                if dir_id:
                    msg = f"Error: child folder {final} already exists in the folder {pathsofar}"
                    self.save_progress(msg)
                    return action_result.set_status(phantom.APP_ERROR, msg)

                dir_id = self._new_child_folder(action_result, final, parent_id, email, pathsofar)
                action_result.add_data(self._currentdir)

        except ReturnException as e:
            self._dump_error_log(e)
            return action_result.get_status()

        action_result.update_summary(
            {
                "folders created": len(action_result.get_data()),
                "folder": self._currentdir["id"],
            }
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_folder_id(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email = param["email_address"]
        folder = param["folder"]

        try:
            dir_id, error, ret = self._get_folder_id(action_result, folder, email)

        except ReturnException as e:
            self._dump_error_log(e)
            return action_result.get_status()

        if ret and len(ret) > 0:
            for x in ret:
                action_result.add_data(x)

        if dir_id:
            action_result.update_summary({"folder_id": dir_id})
            return action_result.set_status(phantom.APP_SUCCESS)

        else:
            self.save_progress(error)
            return action_result.set_status(phantom.APP_ERROR, error)

    def _email_to_recipient(self, email: str):
        recipient = {"emailAddress": {"address": email}}
        return recipient

    def _create_draft_message(
        self,
        action_result,
        subject: str,
        body: str,
        from_email: str,
        *,
        to_emails: list[str],
        cc_emails: list[str],
        bcc_emails: list[str],
        headers: dict[str, str],
    ):
        endpoint = f"/users/{from_email}/messages"
        req_headers = {"Prefer": 'IdType="ImmutableId"'}
        msg = {"subject": subject, "body": {"contentType": "HTML", "content": body}}
        if to_emails:
            msg["toRecipients"] = [self._email_to_recipient(email) for email in to_emails]
        if cc_emails:
            msg["ccRecipients"] = [self._email_to_recipient(email) for email in cc_emails]
        if bcc_emails:
            msg["bccRecipients"] = [self._email_to_recipient(email) for email in bcc_emails]
        if headers:
            msg["internetMessageHeaders"] = [{"name": key, "value": value} for key, value in headers.items()]

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, method="post", headers=req_headers, data=json.dumps(msg))

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        message_id = response["id"]
        return action_result, message_id

    def _send_draft_message(self, action_result, user_id, message_id):
        endpoint = f"/users/{user_id}/messages/{message_id}/send"

        ret_val, _ = self._make_rest_call_helper(action_result, endpoint, method="post")
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, f"Failed to send draft email with id: {message_id}"), None

        return action_result, message_id

    def _get_vault_info(self, vault_id):
        _, _, vault_infos = phantom_vault.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
        if not vault_infos:
            _, _, vault_infos = phantom_vault.vault_info(vault_id=vault_id)
        return vault_infos[0] if vault_infos else None

    def _add_attachment_to_message(self, action_result, vault_id, user_id, message_id):
        vault_info = self._get_vault_info(vault_id)
        if not vault_info:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to find vault entry {vault_id}"), None

        if vault_info["size"] > MSGOFFICE365_UPLOAD_SESSION_CUTOFF:
            ret_val, attachment_id = self._upload_large_attachment(action_result, vault_info, user_id, message_id)
        else:
            ret_val, attachment_id = self._upload_small_attachment(action_result, vault_info, user_id, message_id)

        return ret_val, attachment_id

    def _upload_small_attachment(self, action_result, vault_info, user_id, message_id):
        endpoint = f"/users/{user_id}/messages/{message_id}/attachments"
        with open(vault_info["path"], mode="rb") as file:
            file_content = file.read()
        data = {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": vault_info["name"],
            "contentType": vault_info["mime_type"],
            "contentBytes": base64.b64encode(file_content).decode("ascii"),
            "contentId": vault_info["vault_id"],
        }
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, method="post", data=json.dumps(data))
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Failed to upload vault entry {}".format(vault_info["vault_id"])), None
        attachment_id = response["id"]
        return phantom.APP_SUCCESS, attachment_id

    def _upload_large_attachment(self, action_result, vault_info, user_id, message_id):
        endpoint = f"/users/{user_id}/messages/{message_id}/attachments/createUploadSession"
        file_size = vault_info["size"]
        data = {
            "AttachmentItem": {
                "attachmentType": "file",
                "name": vault_info["name"],
                "contentType": vault_info["mime_type"],
                "contentId": vault_info["vault_id"],
                "size": file_size,
            }
        }
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, method="post", data=json.dumps(data))
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Failed to upload vault entry {}".format(vault_info["vault_id"])), None
        upload_url = response["uploadUrl"]

        with open(vault_info["path"], mode="rb") as file:
            for start_position in range(0, file_size, MSGOFFICE365_UPLOAD_LARGE_FILE_CUTOFF):
                file_content = file.read(MSGOFFICE365_UPLOAD_LARGE_FILE_CUTOFF)
                end_position = start_position + len(file_content) - 1
                headers = {
                    "Content-Type": "application/octet-stream",
                    "Content-Range": f"bytes {start_position}-{end_position}/{file_size}",
                }
                flag = True
                while flag:
                    response = requests.put(upload_url, headers=headers, data=file_content)

                    if response.status_code == 429 and response.headers["Retry-After"]:
                        retry_time = int(response.headers["Retry-After"])

                        if retry_time > 300:  # throw error if wait time greater than 300 seconds
                            self.debug_print("Retry is canceled as retry time is greater than 300 seconds")
                            self._process_response(response, action_result)
                            return (
                                action_result.set_status(
                                    phantom.APP_ERROR,
                                    f"Failed to upload file, {action_result.get_message()} Please retry after \
                                    {retry_time} seconds",
                                ),
                                None,
                            )
                        self.debug_print(f"Retrying after {retry_time} seconds")
                        time.sleep(retry_time + 1)
                    elif not response.ok:
                        return (
                            action_result.set_status(
                                phantom.APP_ERROR,
                                f"Failed to upload file, Error occurred : {response.status_code}, {response.text!s}",
                            ),
                            None,
                        )
                    else:
                        flag = False

        result_location = response.headers.get("Location", "no_location_found")
        match = re.search(r"Attachments\('(?P<attachment_id>[^']+)'\)", result_location)
        if not match:
            return action_result.set_status(phantom.APP_ERROR, f"Unable to extract attachment id from url {result_location}"), None
        attachment_id = match.group("attachment_id")
        return phantom.APP_SUCCESS, attachment_id

    def _get_message(self, action_result, user_id, message_id):
        endpoint = f"/users/{user_id}/messages/{message_id}"

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, method="get")
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, f"Failed to get email with id: {message_id}"), None

        return action_result, response

    def _handle_send_email(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        from_email = param.get("from") or config.get("email_address")
        to_emails = [email for x in param.get("to", "").split(",") if (email := x.strip())]
        cc_emails = [email for x in param.get("cc", "").split(",") if (email := x.strip())]
        bcc_emails = [email for x in param.get("bcc", "").split(",") if (email := x.strip())]

        subject = param["subject"]

        try:
            headers = json.loads(param.get("headers", "{}"))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please enter headers in a valid JSON format")

        body = param["body"]
        vault_ids = [vault_id for x in param.get("attachments", "").split(",") if (vault_id := x.strip())]

        self.save_progress("Creating draft message")
        ret_val, message_id = self._create_draft_message(
            action_result, subject, body, from_email, headers=headers, to_emails=to_emails, cc_emails=cc_emails, bcc_emails=bcc_emails
        )
        if phantom.is_fail(ret_val):
            return action_result
        self.save_progress(f"Created draft message with id: {message_id}")

        attachments = []
        for vault_id in vault_ids:
            self.save_progress(f"Creating attachment for vault id: {vault_id}")
            ret_val, attachment_id = self._add_attachment_to_message(action_result, vault_id, from_email, message_id)
            if phantom.is_fail(ret_val):
                return action_result
            self.save_progress(f"Created attachment with id: {attachment_id}")
            attachment = {"vault_id": vault_id, "attachment_id": attachment_id}
            attachments.append(attachment)

        self.save_progress(f"Sending draft email with id: {message_id}")
        ret_val, message_id = self._send_draft_message(action_result, from_email, message_id)
        if phantom.is_fail(ret_val):
            return action_result
        self.save_progress("Successfully sent draft email.")

        self.save_progress(f"Getting sent email details with id: {message_id}")
        ret_val, message_details = self._get_message(action_result, from_email, message_id)
        if phantom.is_fail(ret_val):
            return action_result
        self.save_progress("Got sent email details.")

        action_result.add_data(message_details)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully sent email")

    def _paginator(self, action_result, endpoint, limit=None, params=None, query=None, is_advance_query=False):
        """
        This action is used to create an iterator that will paginate through responses from called methods.

        :param method_name: Name of method whose response is to be paginated
        :param action_result: Object of ActionResult class
        :param **kwargs: Dictionary of Input parameters
        """

        list_items = list()
        next_link = None
        headers = {}

        # maximum page size
        page_size = MSGOFFICE365_PER_PAGE_COUNT

        if limit and limit < page_size:
            page_size = limit

        if isinstance(params, dict):
            params.update({"$top": page_size})
        else:
            params = {"$top": page_size}

        if query:
            params.update({"$filter": query})

        if is_advance_query:
            params["$count"] = "true"
            headers["ConsistencyLevel"] = "eventual"

        while True:
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, nextLink=next_link, params=params, headers=headers)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            if response.get("value"):
                list_items.extend(response.get("value"))

            if limit and len(list_items) >= limit:
                return phantom.APP_SUCCESS, list_items[:limit]

            next_link = response.get("@odata.nextLink")
            if not next_link:
                break

            params = None

        return phantom.APP_SUCCESS, list_items

    def _handle_update_email(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(param))

        email_addr = param["email_address"]
        message_id = param["id"]

        endpoint = f"/users/{email_addr}/messages/{message_id}"

        categories = param.get("categories")
        subject = param.get("subject")

        if subject is None and categories is None:
            return action_result.set_status(phantom.APP_ERROR, "Please specify one of the email properties to update")

        data_to_send = {}
        if categories is not None:
            categories = [x.strip() for x in categories.split(",")]
            data_to_send["categories"] = categories

        if subject is not None:
            data_to_send["subject"] = subject

        self.save_progress("Updating email")
        ret_val, _ = self._make_rest_call_helper(action_result, endpoint, method="patch", data=json.dumps(data_to_send))
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress(f"Getting sent email details with id: {message_id}")
        ret_val, message_details = self._get_message(action_result, email_addr, message_id)
        if phantom.is_fail(ret_val):
            return action_result
        self.save_progress("Got sent email details.")

        action_result.add_data(message_details)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated email")

    def _handle_block_sender(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        message = param["message_id"]
        user = param["user_id"]
        move_to_junk_folder = param.get("move_to_junk_folder", False)

        endpoint = f"/users/{user}/messages/{message}/markAsJunk"
        self.save_progress(f"endpoint {endpoint}")

        ret_val, response = self._make_rest_call_helper(
            action_result, endpoint, data=json.dumps({"moveToJunk": move_to_junk_folder}), method="post", beta=True
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, f"Moving email  with id: {message} to junk folder failed")

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_sender(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        message = param["message_id"]
        user = param["user_id"]
        move_to_inbox = param.get("move_to_inbox", False)

        endpoint = f"/users/{user}/messages/{message}/markAsNotJunk"
        self.save_progress(f"endpoint {endpoint}")

        ret_val, response = self._make_rest_call_helper(
            action_result, endpoint, data=json.dumps({"moveToInbox": move_to_inbox}), method="post", beta=True
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, f"Moving email  with id: {message} to inbox folder failed")

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_resolve_name(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        # id or userPrincipalName
        email = param["email"]

        endpoint = f"/users?$filter=startswith(displayName,'{email}') or startswith(mail,'{email}')"
        ret_val, responses = self._make_rest_call_helper(action_result, endpoint)
        self.save_progress(f"Fetching user ended witch {ret_val}")

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Got invalid ret val")

        for response in responses.get("value"):
            user_id = response.get("id")

            endpoint_other_mails = f"/users/{user_id}?$select=mailNickname,proxyAddresses,otherMails"
            endpoint_other_address = f"/users/{user_id}?$select=city,state,street,postalCode"
            endpoint_mailbox = f"/users/{user_id}/mailboxSettings/userPurpose"

            ret_val_proxy, response_proxy = self._make_rest_call_helper(action_result, endpoint_other_mails)
            ret_val_address, response_address = self._make_rest_call_helper(action_result, endpoint_other_address)
            ret_val_mailbox, response_mailbox = self._make_rest_call_helper(action_result, endpoint_mailbox)

            self.save_progress(f"Got statuses: mails: {ret_val_proxy}, address: {ret_val_address}, mailbox: {ret_val_mailbox}")

            action_result.add_data(response | response_proxy | response_address | (response_mailbox or {"userPurpose": None}))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_mailbox_messages(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_address = param["email_address"]
        folder = param.get("folder", MSGOFFICE365_DEFAULT_FOLDER)
        limit = param.get("limit", MSGOFFICE365_DEFAULT_LIMIT)
        offset = param.get("offset", 0)
        ingest = param.get("plus_ingest", False)
        download_attachments = param.get("download_attachments", False)
        download_email = param.get("download_email", False)
        extract_headers = param.get("extract_headers", False)

        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Limit should not exceed 100 per request for timeout reasons
        if limit > 100:
            return action_result.set_status(phantom.APP_ERROR, "Limit should not exceed 100 messages per request")

        ret_val, offset = _validate_integer(action_result, offset, "'offset' action", allow_zero=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = f"/users/{email_address}/mailFolders/{folder}/messages"
        params = {
            "$top": limit,
            "$orderby": MSGOFFICE365_ORDERBY_RECEIVED_DESC,
            "$select": ",".join(MSGOFFICE365_SELECT_PARAMETER_LIST),
            "$skip": offset,
        }

        date_filters = []
        if param.get("start_date"):
            date_filters.append(MSGOFFICE365_RECEIVED_DATE_FILTER.format(operator="ge", date=param.get("start_date")))
        if param.get("end_date"):
            date_filters.append(MSGOFFICE365_RECEIVED_DATE_FILTER.format(operator="le", date=param.get("end_date")))

        if date_filters:
            params["$filter"] = MSGOFFICE365_DATE_FILTER_AND.join(date_filters)

        ret_val, messages = self._paginator(action_result, endpoint, limit=limit, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        failed_email_ids = 0
        duplicate_count = self._duplicate_count
        total_emails = len(messages)

        for index, email in enumerate(messages):
            try:
                # Perform additional processing of attachments/data for email
                message_endpoint = f"/users/{email_address}/messages/{email['id']}"
                email = self._process_email_details(
                    action_result,
                    email,
                    email_address,
                    message_endpoint,
                    extract_headers=extract_headers,
                    download_attachments=download_attachments,
                    download_email=download_email,
                )

                action_result.add_data(email)

                if ingest:
                    try:
                        # Ingest email data
                        ret_val = self._process_email_data(self.get_config(), action_result, endpoint, email)
                        if phantom.is_fail(ret_val):
                            failed_email_ids += 1
                            continue

                    except Exception as e:
                        failed_email_ids += 1
                        self.debug_print(f"Exception occurred while processing email ID: {email.get('id')}. Error: {e!s}")

            except Exception as e:
                failed_email_ids += 1
                self.debug_print(f"Exception occurred while processing email ID: {email.get('id')}. Error: {e!s}")

        if failed_email_ids == total_emails and total_emails > 0:
            return action_result.set_status(phantom.APP_ERROR, f"Error occurred while processing all {total_emails} email IDs.")

        summary = action_result.update_summary({})
        summary["total_messages"] = total_emails
        if ingest:
            duplicate_count = self._duplicate_count - duplicate_count
            summary["new_emails_ingested"] = total_emails - failed_email_ids - duplicate_count
            summary["duplicate_emails"] = duplicate_count
            summary["failed_emails"] = failed_email_ids

        status_msg = f"Successfully retrieved {total_emails} messages from {email_address}'s {folder} folder (offset: {offset})"
        if ingest:
            status_msg += f" and ingested {total_emails - failed_email_ids - duplicate_count} new messages"
            if duplicate_count:
                status_msg += f" ({duplicate_count} duplicates skipped)"
            if failed_email_ids:
                status_msg += f" ({failed_email_ids} failed)"

        return action_result.set_status(phantom.APP_SUCCESS, status_msg)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "resolve_name":
            ret_val = self._handle_resolve_name(param)

        if action_id == "block_sender":
            ret_val = self._handle_block_sender(param)

        if action_id == "unblock_sender":
            ret_val = self._handle_unblock_sender(param)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "copy_email":
            ret_val = self._handle_copy_email(param)

        elif action_id == "move_email":
            ret_val = self._handle_move_email(param)

        elif action_id == "delete_email":
            ret_val = self._handle_delete_email(param)

        elif action_id == "delete_event":
            ret_val = self._handle_delete_event(param)

        elif action_id == "get_email":
            ret_val = self._handle_get_email(param)

        elif action_id == "get_email_properties":
            ret_val = self._handle_get_email_properties(param)

        elif action_id == "on_poll":
            ret_val = self._handle_on_poll(param)

        elif action_id == "run_query":
            ret_val = self._handle_run_query(param)

        elif action_id == "list_events":
            ret_val = self._handle_list_events(param)

        elif action_id == "list_groups":
            ret_val = self._handle_list_groups(param)

        elif action_id == "list_group_members":
            ret_val = self._handle_list_group_members(param)

        elif action_id == "list_users":
            ret_val = self._handle_list_users(param)

        elif action_id == "list_folders":
            ret_val = self._handle_list_folders(param)

        elif action_id == "oof_check":
            ret_val = self._handle_oof_check(param)

        elif action_id == "generate_token":
            ret_val = self._handle_generate_token(param)

        elif action_id == "create_folder":
            ret_val = self._handle_create_folder(param)

        elif action_id == "get_folder_id":
            ret_val = self._handle_get_folder_id(param)

        elif action_id == "list_rules":
            ret_val = self._handle_list_rules(param)

        elif action_id == "get_rule":
            ret_val = self._handle_get_rule(param)

        elif action_id == "send_email":
            ret_val = self._handle_send_email(param)

        elif action_id == "update_email":
            ret_val = self._handle_update_email(param)

        elif action_id == "get_mailbox_messages":
            ret_val = self._handle_get_mailbox_messages(param)

        return ret_val

    def _get_private_key(self, action_result):
        # When the private key is copied/pasted to an asset parameter
        # SOAR converts \n to spaces. This code fixes that and rebuilds
        # the private key as it should be

        if self._certificate_private_key is not None:
            p = re.compile("(-----.*?-----) (.*) (-----.*?-----)")
            m = p.match(self._certificate_private_key)

            if m:
                private_key = "\n".join([m.group(1), m.group(2).replace(" ", "\n"), m.group(3)])
                return phantom.APP_SUCCESS, private_key
            else:
                return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_CBA_KEY_ERROR), None

    def _generate_new_cba_access_token(self, action_result):
        self.save_progress("Generating token using Certificate Based Authentication...")

        # reset the state
        self._state.pop("admin_auth", None)
        self._state.pop("non_admin_auth", None)

        # Certificate Based Authentication requires both Certificate Thumbprint and Certificate Private Key
        if not (self._thumbprint and self._certificate_private_key):
            self.save_progress(MSGOFFICE365_CBA_AUTH_ERROR)
            return self.set_status(phantom.APP_ERROR), None

        # Check non-interactive is enabled for CBA auth
        if not self._admin_consent:
            self.save_progress(MSGOFFICE365_CBA_ADMIN_CONSENT_ERROR)
            return self.set_status(phantom.APP_ERROR), None

        ret_val, self._private_key = self._get_private_key(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        try:
            app = msal.ConfidentialClientApplication(
                self._client_id,
                authority=MSGOFFICE365_AUTHORITY_URL.format(tenant=self._tenant),
                client_credential={"thumbprint": self._thumbprint, "private_key": self._private_key},
            )
        except Exception as e:
            error_msg = _get_error_msg_from_exception(e, self)
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please check your configured parameters. Error while using certificate to authenticate. {error_msg}",
                ),
                None,
            )

        self.debug_print("Requesting new token from Azure AD.")
        res_json = app.acquire_token_for_client(scopes=[MSGOFFICE365_DEFAULT_SCOPE])

        if error := res_json.get("error"):
            # replace thumbprint to dummy value
            error_message = f"{error}: {res_json.get('error_description')}".replace(self._thumbprint[4:], "xxxxxxxxxxxxxxxxxxx")
            return action_result.set_status(phantom.APP_ERROR, error_message), None

        return phantom.APP_SUCCESS, res_json

    def _generate_new_oauth_access_token(self, action_result):
        self.save_progress("Generating token using OAuth Authentication...")
        req_url = SERVER_TOKEN_URL.format(self._tenant)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
        }

        if not self._admin_access:
            data["scope"] = "offline_access " + self._scope
        else:
            data["scope"] = MSGOFFICE365_DEFAULT_SCOPE

        if not self._admin_access:
            if self._state.get("code"):
                self.save_progress("Generating token using authorization code")
                data["redirect_uri"] = self._state.get("redirect_uri")
                data["code"] = self._state.get("code")
                data["grant_type"] = "authorization_code"
                self._state.pop("code")
            elif self._refresh_token:
                self.save_progress("Generating token using refresh token")
                data["refresh_token"] = self._refresh_token
                data["grant_type"] = "refresh_token"
            else:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Unexpected details retrieved from the state file.",
                )

        self.debug_print("Generating token...")
        return self._make_rest_call(action_result, req_url, headers=headers, data=data, method="post")

    def _get_token(self, action_result):
        # Determine the authentication type and function to generate the access token
        # Automatic auth -  If client Secret exists, it will take priority and follow the OAuth workflow.
        auth_type, generate_token_func = (
            ("cba", self._generate_new_cba_access_token)
            if self._auth_type == "cba" or not self._client_secret
            else ("oauth", self._generate_new_oauth_access_token)
        )

        # Attempt to generate the access token and check for failure
        ret_val, resp_json = generate_token_func(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Save the determined auth type
        self._state["auth_type"] = auth_type

        if auth_type == "cba" and self._admin_consent:
            self._state["admin_consent"] = True

        # Save the response on the basis of admin_access
        if self._admin_access:
            # if admin consent already provided, save to state
            if self._admin_consent:
                self._state["admin_consent"] = True
            self._state["admin_auth"] = resp_json
        else:
            self._state["non_admin_auth"] = resp_json

        # Fetching the access token and refresh token
        self._access_token = resp_json.get("access_token")
        self._refresh_token = resp_json.get("refresh_token")

        # Save state
        self.save_state(self._state)
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print(MSGOFFICE365_STATE_FILE_CORRUPT_ERROR)
            self._reset_state_file()

            return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_STATE_FILE_CORRUPT_ERROR)

        # Scenario -
        #
        # If the corresponding state file doesn't have correct owner, owner group or permissions,
        # the newly generated token is not being saved to state file and automatic workflow for token has been stopped.
        # So we have to check that token from response and token which are saved to state file
        # after successful generation of new token are same or not.

        if self._admin_access:
            if self._access_token != self._state.get("admin_auth", {}).get("access_token"):
                return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_INVALID_PERMISSION_ERROR)
        else:
            if self._access_token != self._state.get("non_admin_auth", {}).get("access_token"):
                return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_INVALID_PERMISSION_ERROR)

        self.debug_print("Token generated successfully")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_consent(self, action_result):
        self.save_progress("Getting App REST endpoint URL")

        # Get the URL to the app's REST Endpoint, this is the url that the TC dialog
        # box will ask the user to connect to
        ret_val, app_rest_url = self._get_url_to_app_rest(action_result)
        app_state = {}
        if phantom.is_fail(ret_val):
            self.save_progress(f"Unable to get the URL to the app's REST Endpoint. Error: {action_result.get_message()}")
            return action_result.set_status(phantom.APP_ERROR)

        # create the url that the oauth server should re-direct to after the auth is completed
        # (success and failure), this is added to the state so that the request handler will access
        # it later on
        redirect_uri = f"{app_rest_url}/result"
        app_state["redirect_uri"] = redirect_uri

        self.save_progress("Using OAuth Redirect URL as:")
        self.save_progress(redirect_uri)

        if self._admin_access:
            # Create the url for fetching administrator consent
            admin_consent_url = f"https://login.microsoftonline.com/{self._tenant}/adminconsent"
            admin_consent_url += f"?client_id={self._client_id}"
            admin_consent_url += f"&redirect_uri={redirect_uri}"
            admin_consent_url += f"&state={self._asset_id}"
        else:
            # Scope is required for non-admin access
            if not self._scope:
                self.save_progress(MSGOFFICE365_NON_ADMIN_SCOPE_ERROR)
                return action_result.set_status(phantom.APP_ERROR)
            # Create the url authorization, this is the one pointing to the oauth server side
            admin_consent_url = f"https://login.microsoftonline.com/{self._tenant}/oauth2/v2.0/authorize"
            admin_consent_url += f"?client_id={self._client_id}"
            admin_consent_url += f"&redirect_uri={redirect_uri}"
            admin_consent_url += f"&state={self._asset_id}"
            admin_consent_url += f"&scope={self._scope}"
            admin_consent_url += "&response_type=code"

        app_state["admin_consent_url"] = admin_consent_url

        # The URL that the user should open in a different tab.
        # This is pointing to a REST endpoint that points to the app
        url_to_show = f"{app_rest_url}/start_oauth?asset_id={self._asset_id}&"

        # Save the state, will be used by the request handler
        _save_app_state(app_state, self._asset_id, self)

        self.save_progress("Please connect to the following URL from a different tab to continue the connectivity process")
        self.save_progress(url_to_show)
        self.save_progress(MSGOFFICE365_AUTHORIZE_TROUBLESHOOT_MSG)

        time.sleep(5)

        completed = False

        app_dir = os.path.dirname(os.path.abspath(__file__))
        auth_status_file_path = f"{app_dir}/{self._asset_id}_{TC_FILE}"

        if self._admin_access:
            self.save_progress("Waiting for Admin Consent to complete")
        else:
            self.save_progress("Waiting for Authorization to complete")

        for i in range(0, 40):
            self.send_progress("{}".format("." * (i % 10)))

            if os.path.isfile(auth_status_file_path):
                completed = True
                os.unlink(auth_status_file_path)
                break

            time.sleep(TC_STATUS_SLEEP)

        if not completed:
            self.save_progress("Authentication process does not seem to be completed. Timing out")
            return action_result.set_status(phantom.APP_ERROR)

        self.send_progress("")

        # Load the state again, since the http request handlers would have saved the result of the admin consent or authorization
        self._state = _load_app_state(self._asset_id, self)

        if not self._state:
            self.save_progress("Authorization not received or not given")
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR)
        else:
            if self._admin_access:
                if not self._state.get("admin_consent"):
                    self.save_progress("Admin Consent not received or not given")
                    self.save_progress("Test Connectivity Failed")
                    return action_result.set_status(phantom.APP_ERROR)
            else:
                if not self._state.get("code"):
                    self.save_progress("Authorization code not received or not given")
                    self.save_progress("Test Connectivity Failed")
                    return action_result.set_status(phantom.APP_ERROR)

        # Deleting the local state file because of it replicates with actual state file while installing the app
        current_file_path = pathlib.Path(__file__).resolve()
        input_file = f"{self._asset_id}_state.json"
        state_file_path = current_file_path.with_name(input_file)
        state_file_path.unlink()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _reset_state_file(self):
        """
        This method resets the state file.
        """
        self.debug_print("Resetting the state file with the default format")
        self._state = {"app_version": self.get_app_json().get("app_version")}

    def initialize(self):
        action_id = self.get_action_identifier()
        action_result = ActionResult()

        self._currentdir = None

        # Load the state in initialize
        config = self.get_config()
        self._asset_id = self.get_asset_id()

        self._tenant = config["tenant"]
        self._client_id = config["client_id"]
        self._auth_type = MSGOFFICE365_AUTH_TYPES.get(config.get("auth_type", MSGOFFICE365_AUTH_AUTOMATIC))
        self._client_secret = config.get("client_secret")
        self._admin_access = config.get("admin_access")
        self._admin_consent = config.get("admin_consent")
        self._thumbprint = config.get("certificate_thumbprint")
        self._certificate_private_key = config.get("certificate_private_key")
        self._scope = config.get("scope") if config.get("scope") else None

        if self._auth_type == "cba":
            # Certificate Based Authentication requires both Certificate Thumbprint and Certificate Private Key
            if not (self._thumbprint and self._certificate_private_key):
                return self.set_status(phantom.APP_ERROR, MSGOFFICE365_CBA_AUTH_ERROR)

            # Check non-interactive is enabled for CBA auth
            if not self._admin_consent:
                return self.set_status(phantom.APP_ERROR, MSGOFFICE365_CBA_ADMIN_CONSENT_ERROR)
        elif self._auth_type == "oauth":
            # OAuth Authentication requires Client Secret
            if not self._client_secret:
                return self.set_status(phantom.APP_ERROR, MSGOFFICE365_OAUTH_AUTH_ERROR)
        else:
            # Must either supply cba or oauth credentials for automatic auth
            if not self._client_secret and not (self._thumbprint and self._certificate_private_key):
                return self.set_status(phantom.APP_ERROR, MSGOFFICE365_AUTOMATIC_AUTH_ERROR)

        self._number_of_retries = config.get("retry_count", MSGOFFICE365_DEFAULT_NUMBER_OF_RETRIES)
        ret_val, self._number_of_retries = _validate_integer(
            self, self._number_of_retries, "'Maximum attempts to retry the API call' asset configuration"
        )

        if phantom.is_fail(ret_val):
            return self.get_status()

        self._retry_wait_time = config.get("retry_wait_time", MSGOFFICE365_DEFAULT_RETRY_WAIT_TIME)
        ret_val, self._retry_wait_time = _validate_integer(
            self,
            self._retry_wait_time,
            "'Delay in seconds between retries' asset configuration",
        )
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Load all the asset configuration in global variables
        self._state = self.load_state()

        if not self._admin_access:
            if not self._scope and self._auth_type == "oauth":
                return self.set_status(phantom.APP_ERROR, MSGOFFICE365_NON_ADMIN_SCOPE_ERROR)

            self._access_token = self._state.get("non_admin_auth", {}).get("access_token", None)
            self._refresh_token = self._state.get("non_admin_auth", {}).get("refresh_token", None)
        else:
            self._access_token = self._state.get("admin_auth", {}).get("access_token", None)

        if action_id == "test_connectivity":
            # User is trying to complete the authentication flow, so just return True from here so that test connectivity continues
            return phantom.APP_SUCCESS

        admin_consent = self._state.get("admin_consent")

        # if it was not and the current action is not test connectivity then it's an error
        if self._admin_access and not admin_consent:
            return self.set_status(phantom.APP_ERROR, MSGOFFICE365_RUN_CONNECTIVITY_MSG)

        if not self._admin_access and not self._access_token:
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return self.set_status(
                    phantom.APP_ERROR,
                    f"{MSGOFFICE365_RUN_CONNECTIVITY_MSG}. {action_result.get_message()}",
                )

        # Create ProcessEmail Object for on_poll
        self._process_email = ProcessEmail(self, config)

        return phantom.APP_SUCCESS

    def _get_fips_enabled(self):
        try:
            from phantom_common.install_info import is_fips_enabled
        except ImportError:
            return False

        fips_enabled = is_fips_enabled()
        if fips_enabled:
            self.debug_print("FIPS is enabled")
        else:
            self.debug_print("FIPS is not enabled")
        return fips_enabled

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="verify",
        required=False,
        default=False,
    )

    args = argparser.parse_args()
    session_id = None
    verify = args.verify

    if args.username and args.password:
        login_url = f"{BaseConnector._get_phantom_base_url()}login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies["csrftoken"]
            data = {
                "username": args.username,
                "password": args.password,
                "csrfmiddlewaretoken": csrftoken,
            }
            headers = {
                "Cookie": f"csrftoken={csrftoken}",
                "Referer": login_url,
            }

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url,
                verify=verify,
                data=data,
                headers=headers,
                timeout=MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT,
            )
            session_id = r2.cookies["sessionid"]

        except Exception as e:
            print(f"Unable to get session id from the platform. Error: {e!s}")
            sys.exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = Office365Connector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
