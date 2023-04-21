# File: office365_connector.py
#
# Copyright (c) 2017-2022 Splunk Inc.
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
import pwd
import sys
import tempfile
import time
from copy import deepcopy
from datetime import datetime

import encryption_helper
import phantom.app as phantom
import phantom.rules as ph_rules
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
MSGRAPH_API_URL = "https://graph.microsoft.com/v1.0"
MAX_END_OFFSET_VAL = 2147483646


class ReturnException(Exception):
    pass


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


def _load_app_state(asset_id, app_connector=None):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)
    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    state = {}
    try:
        with open(real_state_file_path, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            error_msg = _get_error_message_from_exception(e)
            app_connector.debug_print('In _load_app_state: {0}'.format(error_msg))

    if app_connector:
        app_connector.debug_print('Loaded state: ', state)

    try:
        state = _decrypt_state(state, asset_id)
    except Exception as e:
        if app_connector:
            app_connector.debug_print("{}: {}".format(MSGOFFICE365_DECRYPTION_ERR, str(e)))
        state = {}

    return state


def _save_app_state(state, asset_id, app_connector):
    """ This function is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)

    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    try:
        state = _encrypt_state(state, asset_id)
    except Exception as e:
        if app_connector:
            app_connector.debug_print("{}: {}".format(MSGOFFICE365_ENCRYPTION_ERR, str(e)))
        return phantom.APP_ERROR

    if app_connector:
        app_connector.debug_print('Saving state: ', state)

    try:
        with open(real_state_file_path, 'w+') as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        error_msg = _get_error_message_from_exception(e)
        if app_connector:
            app_connector.debug_print('Unable to save state file: {0}'.format(error_msg))
        print('Unable to save state file: {0}'.format(error_msg))
        return phantom.APP_ERROR

    return phantom.APP_SUCCESS


def _get_error_message_from_exception(e):
    """
    Get appropriate error message from the exception.
    :param e: Exception object
    :return: error message
    """
    error_code = None
    error_msg = ERR_MSG_UNAVAILABLE

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
        error_text = "Error Message: {}".format(error_msg)
    else:
        error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

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
                return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_VALID_INT_MSG.format(param=key)), None

            parameter = int(parameter)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_VALID_INT_MSG.format(param=key)), None

        if parameter < 0:
            return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_NON_NEG_INT_MSG.format(param=key)), None
        if not allow_zero and parameter == 0:
            return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

    return phantom.APP_SUCCESS, parameter


def _handle_oauth_result(request, path_parts):
    """
    <base_url>?admin_consent=True&tenant=a417c578-c7ee-480d-a225-d48057e74df5&state=13
    """
    asset_id = request.GET.get('state')
    if not asset_id:
        return HttpResponse("ERROR: Asset ID not found in URL\n{0}".format(json.dumps(request.GET)), content_type="text/plain", status=400)

    # first check for error info
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')

    if error:
        message = "Error: {0}".format(error)
        if error_description:
            message += " Details: {0}".format(error_description)
        return HttpResponse("Server returned {0}".format(message), content_type="text/plain", status=400)

    admin_consent = request.GET.get('admin_consent')
    code = request.GET.get('code')

    if not admin_consent and not code:
        return HttpResponse("ERROR: admin_consent or authorization code not found in URL\n{0}".format(
            json.dumps(request.GET)), content_type="text/plain", status=400)

    # Load the data
    state = _load_app_state(asset_id)

    if admin_consent:
        if admin_consent == 'True':
            admin_consent = True
        else:
            admin_consent = False

        state['admin_consent'] = admin_consent
        _save_app_state(state, asset_id, None)

        # If admin_consent is True
        if admin_consent:
            return HttpResponse('Admin Consent received. Please close this window.', content_type="text/plain")
        return HttpResponse('Admin Consent declined. Please close this window and try again later.', content_type="text/plain", status=400)

    # If value of admin_consent is not available, value of code is available
    state['code'] = code
    _save_app_state(state, asset_id, None)

    return HttpResponse('Code received. Please close this window, the action will continue to get new token.', content_type="text/plain")


def _handle_oauth_start(request, path_parts):

    # get the asset id, the state file is created for each asset
    asset_id = request.GET.get('asset_id')
    if not asset_id:
        return HttpResponse("ERROR: Asset ID not found in URL", content_type="text/plain", status=404)

    # Load the state that was created for the asset
    state = _load_app_state(asset_id)
    if not state:
        return HttpResponse(
            'ERROR: The asset ID is invalid or an error occurred while reading the state file', content_type="text/plain", status=400
        )

    # get the url to point to the authorize url of OAuth
    admin_consent_url = state.get('admin_consent_url')

    if not admin_consent_url:
        return HttpResponse("App state is invalid, admin_consent_url key not found", content_type="text/plain", status=400)

    # Redirect to this link, the user will then require to enter credentials interactively
    response = HttpResponse(status=302)
    response['Location'] = admin_consent_url

    return response


def handle_request(request, path_parts):
    """
    request contains the data posted to the rest endpoint, it is the django http request object
    path_parts is a list of the URL tokenized
    """

    # get the type of data requested, it's the last part of the URL used to post to the REST endpoint
    if len(path_parts) < 2:
        return HttpResponse('error: True, message: Invalid REST endpoint request', content_type="text/plain", status=404)

    call_type = path_parts[1]

    if call_type == 'start_oauth':
        # start the authentication process
        return _handle_oauth_start(request, path_parts)

    if call_type == 'result':

        # process the 'code'
        ret_val = _handle_oauth_result(request, path_parts)
        asset_id = request.GET.get('state')
        if asset_id and asset_id.isalnum():
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, asset_id, TC_FILE)
            real_auth_status_file_path = os.path.abspath(auth_status_file_path)
            if not os.path.dirname(real_auth_status_file_path) == app_dir:
                return HttpResponse("Error: Invalid asset_id", content_type="text/plain", status=400)
            open(auth_status_file_path, 'w').close()
            try:
                uid = pwd.getpwnam("apache").pw_uid
                gid = grp.getgrnam("phantom").gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, "0664")
            except Exception:
                pass

        return ret_val

    return HttpResponse('error: Invalid endpoint', content_type="text/plain", status=404)


def _get_dir_name_from_app_name(app_name):

    app_name = ''.join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()

    if not app_name:
        # hardcode it
        app_name = "app_for_phantom"

    return app_name


def _decrypt_state(state, salt):
    """
    Decrypts the state.

    :param state: state dictionary
    :param salt: salt used for decryption
    :return: decrypted state
    """
    if not state.get("is_encrypted"):
        return state

    if "non_admin_auth" in state:
        if state.get("non_admin_auth").get("access_token"):
            state["non_admin_auth"]["access_token"] = encryption_helper.decrypt(state["non_admin_auth"]["access_token"], salt)

        if state.get("non_admin_auth").get("refresh_token"):
            state["non_admin_auth"]["refresh_token"] = encryption_helper.decrypt(state["non_admin_auth"]["refresh_token"], salt)

    if "admin_auth" in state:
        if state.get("admin_auth").get("access_token"):
            state["admin_auth"]["access_token"] = encryption_helper.decrypt(state["admin_auth"]["access_token"], salt)

    if "code" in state:
        state["code"] = encryption_helper.decrypt(state["code"], salt)

    return state


def _encrypt_state(state, salt):
    """
    Encrypts the state.

    :param state: state dictionary
    :param salt: salt used for encryption
    :return: encrypted state
    """
    if "non_admin_auth" in state:
        if state.get("non_admin_auth").get("access_token"):
            state["non_admin_auth"]["access_token"] = encryption_helper.encrypt(state["non_admin_auth"]["access_token"], salt)

        if state.get("non_admin_auth").get("refresh_token"):
            state["non_admin_auth"]["refresh_token"] = encryption_helper.encrypt(state["non_admin_auth"]["refresh_token"], salt)

    if "admin_auth" in state:
        if state.get("admin_auth").get("access_token"):
            state["admin_auth"]["access_token"] = encryption_helper.encrypt(state["admin_auth"]["access_token"], salt)

    if "code" in state:
        state["code"] = encryption_helper.encrypt(state["code"], salt)

    state["is_encrypted"] = True

    return state


class Office365Connector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(Office365Connector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._tenant = None
        self._client_id = None
        self._client_secret = None
        self._admin_access = None
        self._scope = None
        self._access_token = None
        self._refresh_token = None
        self._REPLACE_CONST = "C53CEA8298BD401BA695F247633D0542"  # pragma: allowlist secret
        self._duplicate_count = 0
        self._asset_id = None

    def load_state(self):
        """
        Load the contents of the state file to the state dictionary and decrypt it.

        :return: loaded state
        """
        state = super().load_state()
        try:
            state = _decrypt_state(state, self._asset_id)
        except Exception as e:
            self.debug_print("{}: {}".format(MSGOFFICE365_DECRYPTION_ERR, str(e)))
            state = None

        return state

    def save_state(self, state):
        """
        Encrypt and save the current state dictionary to the the state file.

        :param state: state dictionary
        :return: status
        """
        try:
            state = _encrypt_state(state, self._asset_id)
        except Exception as e:
            self.debug_print("{}: {}".format(MSGOFFICE365_ENCRYPTION_ERR, str(e)))
            return phantom.APP_ERROR

        return super().save_state(state)

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_ERR_EMPTY_RESPONSE.format(code=response.status_code)), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = _get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(error_msg)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        try:
            error_code = ""
            error_text = ""
            error_message = ""
            error = resp_json.get('error', '')
            error_desc = resp_json.get('error_description', '')
            if isinstance(error, dict):
                error_code = error.get('code')
                error_message = error.get('message')

            if error_message:
                try:
                    soup = BeautifulSoup(resp_json.get('error', {}).get('message'), "html.parser")
                    # Remove the script, style, footer and navigation part from the HTML message
                    for element in soup(["script", "style", "footer", "nav"]):
                        element.extract()
                    error_text = soup.text
                    split_lines = error_text.split('\n')
                    split_lines = [x.strip() for x in split_lines if x.strip()]
                    error_text = '\n'.join(split_lines)
                    if len(error_text) > 500:
                        error_text = 'Error while connecting to a server (Please check input parameters or asset configuration parameters)'
                except Exception:
                    error_text = "Cannot parse error details"

            if error_code:
                error_text = "{}. {}".format(error_code, error_text)

            if error_desc:
                error_text = "{}. {}".format(error_desc, error_text)

            if not error_text:
                error_text = r.text.replace('{', '{{').replace('}', '}}')
        except Exception:
            error_text = r.text.replace('{', '{{').replace('}', '}}')

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, error_text)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        content_type = r.headers.get('Content-Type', '')
        if 'json' in content_type or 'javascript' in content_type:
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between Splunk SOAR and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        if r.status_code == 404:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Email not found"), None)

        if 200 <= r.status_code <= 204:
            return RetVal(phantom.APP_SUCCESS, None)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, url, verify=True, headers={}, params=None, data=None, method="get", download=False):

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        for _ in range(self._number_of_retries):
            try:
                r = request_func(
                                url,
                                data=data,
                                headers=headers,
                                verify=verify,
                                params=params,
                                timeout=MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT)
            except Exception as e:
                error_msg = _get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error connecting to server. {0}".format(error_msg)), resp_json)
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

        asset_name = resp_json.get('name')

        if not asset_name:
            return (action_result.set_status(phantom.APP_ERROR, "Asset Name for ID: {0} not found".format(self._asset_id), None))

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
            error_msg = _get_error_message_from_exception(e)
            message = (
                "json.dumps failed while updating the container: {}. "
                "Possibly a value in the container dictionary is not encoded properly. "
                "Exception: {}"
            ).format(container_id, error_msg)
            return action_result.set_status(phantom.APP_ERROR, message)

        ret_val, _ = self._make_rest_call(action_result, rest_endpoint, False, data=data, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _get_phantom_base_url(self, action_result):

        ret_val, resp_json = self._make_rest_call(action_result, SPLUNK_SOAR_SYS_INFO_URL.format(url=self.get_phantom_base_url()), False)

        if phantom.is_fail(ret_val):
            return (ret_val, None)

        phantom_base_url = resp_json.get('base_url').rstrip("/")

        if not phantom_base_url:
            return (action_result.set_status(phantom.APP_ERROR,
                    "Splunk SOAR Base URL not found in System Settings. Please specify this value in System Settings"), None)

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

        self.save_progress('Using Splunk SOAR base URL as: {0}'.format(phantom_base_url))

        app_json = self.get_app_json()

        app_name = app_json['name']

        app_dir_name = _get_dir_name_from_app_name(app_name)

        url_to_app_rest = "{0}/rest/handler/{1}_{2}/{3}".format(phantom_base_url, app_dir_name, app_json['appid'], asset_name)

        return (phantom.APP_SUCCESS, url_to_app_rest)

    def _make_rest_call_helper(self, action_result, endpoint, verify=True, headers=None,
                               params=None, data=None, method="get", nextLink=None, download=False):

        if nextLink:
            url = nextLink
        else:
            url = "{0}{1}".format(MSGRAPH_API_URL, endpoint)

        if headers is None:
            headers = {}

        headers.update({
            'Authorization': 'Bearer {0}'.format(self._access_token),
            'Accept': 'application/json',
            'Content-Type': 'application/json'})

        ret_val, resp_json = self._make_rest_call(action_result, url, verify, headers, params, data, method, download=download)

        # If token is expired, generate a new token
        msg = action_result.get_message()

        if msg and 'token is invalid' in msg or ('Access token has expired' in
                msg) or ('ExpiredAuthenticationToken' in msg) or ('AuthenticationFailed' in msg) or ('TokenExpired' in
                    msg) or ('InvalidAuthenticationToken' in msg):

            self.debug_print("Token is invalid/expired. Hence, generating a new token.")
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({'Authorization': 'Bearer {0}'.format(self._access_token)})

            ret_val, resp_json = self._make_rest_call(action_result, url, verify, headers, params, data, method, download=download)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _add_attachment_to_vault(self, attachment, container_id, file_data):
        if hasattr(Vault, 'get_vault_tmp_dir'):
            fd, tmp_file_path = tempfile.mkstemp(dir=Vault.get_vault_tmp_dir())
        else:
            fd, tmp_file_path = tempfile.mkstemp(dir='/opt/phantom/vault/tmp')
        os.close(fd)
        file_mode = "wb" if isinstance(file_data, bytes) else "w"
        with open(tmp_file_path, file_mode) as f:
            f.write(file_data)

        success, message, vault_id = ph_rules.vault_add(
            container=container_id,
            file_location=tmp_file_path,
            file_name=attachment['name']
        )
        if not success:
            self.debug_print("Error adding file to vault: {}".format(message))
            return RetVal(phantom.APP_ERROR, None)
        else:
            return RetVal(phantom.APP_SUCCESS, vault_id)

    def _handle_attachment(self, attachment, container_id, artifact_json=None):

        vault_id = None

        try:
            if 'contentBytes' in attachment:  # Check whether the attachment contains the data
                file_data = base64.b64decode(attachment.pop('contentBytes'))
                ret_val, vault_id = self._add_attachment_to_vault(attachment, container_id, file_data)
                if phantom.is_fail(ret_val):
                    return phantom.APP_ERROR
            else:
                self.debug_print("No content found in the attachment. Hence, skipping the vault file creation.")

        except Exception as e:
            error_msg = _get_error_message_from_exception(e)
            self.debug_print("Error saving file to vault: {0}".format(error_msg))
            return phantom.APP_ERROR

        if artifact_json is None:
            attachment['vaultId'] = vault_id
            return phantom.APP_SUCCESS

        artifact_json['name'] = 'Vault Artifact'
        artifact_json['label'] = 'attachment'
        artifact_json['container_id'] = container_id
        artifact_json['source_data_identifier'] = attachment['id']

        artifact_cef = {}

        artifact_cef['size'] = attachment['size']
        artifact_cef['lastModified'] = attachment['lastModifiedDateTime']
        artifact_cef['filename'] = attachment['name']
        artifact_cef['mimeType'] = attachment['contentType']
        if vault_id:
            artifact_cef['vault_id'] = vault_id

        artifact_json['cef'] = artifact_cef

        return phantom.APP_SUCCESS

    def _handle_item_attachment(self, attachment, container_id, endpoint, action_result):

        vault_id = None

        try:
            attach_endpoint = "{}/{}/$value".format(endpoint, attachment['id'])
            ret_val, rfc822_email = self._make_rest_call_helper(action_result, attach_endpoint, download=True)
            if phantom.is_fail(ret_val):
                self.debug_print("Error while downloading the file content, for attachment id: {}".format(attachment['id']))
                return phantom.APP_ERROR

            attachment['name'] = "{}.eml".format(attachment['name'])

            if rfc822_email:  # Check whether the API returned any data
                ret_val, vault_id = self._add_attachment_to_vault(attachment, container_id, rfc822_email)
                if phantom.is_fail(ret_val):
                    return phantom.APP_ERROR
            else:
                self.debug_print("No content found for the item attachment. Hence, skipping the vault file creation.")

        except Exception as e:
            error_msg = _get_error_message_from_exception(e)
            self.debug_print("Error saving file to vault: {0}".format(error_msg))
            return phantom.APP_ERROR

        attachment['vaultId'] = vault_id
        return phantom.APP_SUCCESS

    def _create_reference_attachment_artifact(self, container_id, attachment, artifact_json):
        """
        Create reference attachment artifact.

        :param container_id: container ID
        :param attachment: attachment dict
        :param artifact_json: artifact dict to add the data
        :return: phantom.APP_SUCCESS
        """
        artifact_json['name'] = 'Reference Attachment Artifact'
        artifact_json['container_id'] = container_id
        artifact_json['source_data_identifier'] = attachment['id']

        artifact_cef = {}

        artifact_cef['size'] = attachment.get('size')
        artifact_cef['lastModified'] = attachment.get('lastModifiedDateTime')
        artifact_cef['filename'] = attachment.get('name')
        artifact_cef['mimeType'] = attachment.get('contentType')

        artifact_json['cef'] = artifact_cef

        return phantom.APP_SUCCESS

    def _create_email_artifacts(self, container_id, email, artifact_id=None):
        """
        Create email artifacts.

        :param container_id: container ID
        :param email: email content
        :param artifact_id: artifact ID
        :return: extracted artifacts list
        """
        artifacts = []

        email_artifact = {}
        email_artifact['label'] = 'email'
        email_artifact['name'] = 'Email Artifact'
        email_artifact['container_id'] = container_id

        if email.get('id'):
            artifact_id = email['id']

            # Set email ID contains
            self._process_email._set_email_id_contains(email['id'])
            email_artifact['cef_types'] = {'messageId': self._process_email._email_id_contains}

        email_artifact['source_data_identifier'] = artifact_id

        cef = {}
        email_artifact['cef'] = cef

        for k, v in email.items():
            if v is not None:
                if k == 'from':
                    from_obj = v.get('emailAddress', {})
                    cef[k] = from_obj
                    cef['fromEmail'] = from_obj.get('address', '')
                elif k == 'toRecipients':
                    cef[k] = v
                    # add first email to To
                    recipients = v
                    if len(recipients):
                        cef['toEmail'] = recipients[0].get('emailAddress', {}).get('address', '')
                elif k == 'id':
                    cef['messageId'] = v
                elif k == 'internetMessageHeaders':
                    cef['internetMessageHeaders'] = {}
                    if isinstance(v, list):
                        for header in v:
                            key_name = header.get('name')
                            key_value = header.get('value')
                            if key_name and key_value:
                                cef['internetMessageHeaders'][key_name] = key_value
                else:
                    cef[k] = v

        if cef.get('body', {}).get('content') and (cef.get('body', {}).get('contentType') == 'html'):
            html_body = cef['body']['content']

            try:
                soup = BeautifulSoup(html_body, "html.parser")
                # Remove the script, style, footer, title and navigation part from the HTML message
                for element in soup(["script", "style", "footer", "title", "nav"]):
                    element.extract()
                body_text = soup.get_text(separator=' ')
                split_lines = body_text.split('\n')
                split_lines = [x.strip() for x in split_lines if x.strip()]
                body_text = '\n'.join(split_lines)
                if body_text:
                    cef['bodyText'] = body_text
            except Exception:
                self.debug_print("Cannot parse email body text details")

        body = email['body']['content']

        ips = []
        self._process_email._get_ips(body, ips)

        for ip in ips:
            ip_artifact = {}
            artifacts.append(ip_artifact)
            ip_artifact['name'] = 'IP Artifact'
            ip_artifact['label'] = 'artifact'
            ip_artifact['cef'] = ip
            ip_artifact['container_id'] = container_id
            ip_artifact['source_data_identifier'] = artifact_id

        urls = []
        domains = []
        self._process_email._extract_urls_domains(body, urls, domains)

        for url in urls:
            url_artifact = {}
            artifacts.append(url_artifact)
            url_artifact['name'] = 'URL Artifact'
            url_artifact['label'] = 'artifact'
            url_artifact['cef'] = url
            url_artifact['container_id'] = container_id
            url_artifact['source_data_identifier'] = artifact_id

        for domain in domains:
            domain_artifact = {}
            artifacts.append(domain_artifact)
            domain_artifact['name'] = 'Domain Artifact'
            domain_artifact['label'] = 'artifact'
            domain_artifact['cef'] = domain
            domain_artifact['container_id'] = container_id
            domain_artifact['source_data_identifier'] = artifact_id

        hashes = []
        self._process_email._extract_hashes(body, hashes)

        for hash in hashes:
            hash_artifact = {}
            artifacts.append(hash_artifact)
            hash_artifact['name'] = 'Hash Artifact'
            hash_artifact['label'] = 'artifact'
            hash_artifact['cef'] = hash
            hash_artifact['container_id'] = container_id
            hash_artifact['source_data_identifier'] = artifact_id

        artifacts.append(email_artifact)

        return artifacts

    def _extract_attachments(self, config, attach_endpoint, artifacts, action_result, attachments, container_id, first_time=False):
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

            if attachment.get('@odata.type') == '#microsoft.graph.itemAttachment':

                # We need to expand the item attachment only once
                if first_time:
                    sub_email_endpoint = attach_endpoint + '/{0}?$expand=microsoft.graph.itemattachment/item'.format(attachment['id'])
                    ret_val, sub_email_resp = self._make_rest_call_helper(action_result, sub_email_endpoint)
                    if phantom.is_fail(ret_val):
                        return action_result.get_status()
                    sub_email = sub_email_resp.get('item', {})

                else:
                    sub_email = attachment.get('item', {})

                # Use recursive approach to extract the reference attachment
                item_attachments = sub_email.pop('attachments', [])
                if item_attachments:
                    ret_val = self._extract_attachments(config, attach_endpoint, artifacts, action_result, item_attachments, container_id)
                    if phantom.is_fail(ret_val):
                        self.debug_print("Error while processing nested attachments, for attachment id: {}".format(attachment['id']))

                if first_time:
                    # Fetch the rfc822 content for the item attachment
                    sub_email_endpoint = '{0}/{1}/$value'.format(attach_endpoint, attachment['id'])
                    attachment['name'] = "{}.eml".format(attachment['name'])
                    ret_val, rfc822_email = self._make_rest_call_helper(action_result, sub_email_endpoint, download=True)
                    if phantom.is_fail(ret_val):
                        self.debug_print("Error while downloading the email content, for attachment id: {}".format(attachment['id']))

                    if rfc822_email:
                        # Create ProcessEmail Object for email item attachment
                        process_email_obj = ProcessEmail(self, config)
                        process_email_obj._trigger_automation = False
                        ret_val, message = process_email_obj.process_email(rfc822_email, attachment['id'], epoch=None, container_id=container_id)
                        if phantom.is_fail(ret_val):
                            self.debug_print("Error while processing the email content, for attachment id: {}".format(attachment['id']))

                        if config.get('ingest_eml', False):
                            # Add eml file into the vault if ingest_email is checked
                            ret_val, vault_id = self._add_attachment_to_vault(attachment, container_id, rfc822_email)
                            if phantom.is_fail(ret_val):
                                self.debug_print('Could not process item attachment. See logs for details')
                            else:
                                # If success, create vault artifact
                                artifact_json = {
                                    'name': 'Vault Artifact',
                                    'label': 'attachment',
                                    'container_id': container_id,
                                    'source_data_identifier': attachment['id']
                                }

                                artifact_cef = {
                                    'size': attachment['size'],
                                    'lastModified': attachment['lastModifiedDateTime'],
                                    'filename': attachment['name'],
                                    'mimeType': attachment['contentType']
                                }
                                if vault_id:
                                    artifact_cef['vault_id'] = vault_id
                                artifact_json['cef'] = artifact_cef
                                artifacts.append(artifact_json)

                    else:
                        self.debug_print("No content found for the item attachment. Hence, skipping the email file processing.")

            elif attachment.get('@odata.type') == "#microsoft.graph.referenceAttachment":

                attach_artifact = {}
                artifacts.append(attach_artifact)
                self._create_reference_attachment_artifact(container_id, attachment, attach_artifact)

            elif attachment.get('name', '').endswith('.eml'):
                if 'contentBytes' in attachment:
                    try:
                        rfc822_email = base64.b64decode(attachment['contentBytes'])
                        rfc822_email = UnicodeDammit(rfc822_email).unicode_markup
                    except Exception as e:
                        error_msg = _get_error_message_from_exception(e)
                        self.debug_print("Unable to decode Email Mime Content. {0}".format(error_msg))
                        return action_result.set_status(phantom.APP_ERROR, "Unable to decode Email Mime Content")

                    # Create ProcessEmail Object for email file attachment
                    process_email_obj = ProcessEmail(self, config)
                    process_email_obj._trigger_automation = False
                    ret_val, message = process_email_obj.process_email(rfc822_email, attachment['id'], epoch=None, container_id=container_id)
                    if phantom.is_fail(ret_val):
                        return action_result.set_status(phantom.APP_ERROR, message)
                else:
                    self.debug_print("No content found in the .eml file attachment. Hence, skipping the email file processing.")

            elif first_time:
                attach_artifact = {}
                artifacts.append(attach_artifact)
                if not self._handle_attachment(attachment, container_id, artifact_json=attach_artifact):
                    return action_result.set_status(phantom.APP_ERROR, "Could not process attachment. See logs for details.")

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

        container['name'] = email['subject'] if email['subject'] else email['id']
        container_description = MSGOFFICE365_CONTAINER_DESCRIPTION.format(last_modified_time=email['lastModifiedDateTime'])
        container['description'] = container_description
        container['source_data_identifier'] = email['id']

        ret_val, message, container_id = self.save_container(container)

        if phantom.is_fail(ret_val) or not container_id:
            return action_result.set_status(phantom.APP_ERROR, message)

        if MSGOFFICE365_DUPLICATE_CONTAINER_FOUND_MSG in message.lower():
            self.debug_print("Duplicate container found")
            self._duplicate_count += 1

            # Prevent further processing if the email is not modified
            ret_val, container_info, status_code = self.get_container_info(container_id=container_id)
            if phantom.is_fail(ret_val):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Status Code: {}. Error occurred while fetching the container info for container ID: {}".format(status_code, container_id)
                )

            if container_info.get('description', '') == container_description:
                msg = "Email ID: {} has not been modified. Hence, skipping the artifact ingestion.".format(email['id'])
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

        if email['hasAttachments'] and config.get('extract_attachments', False):

            attach_endpoint = endpoint + '/{0}/attachments'.format(email['id'])
            ret_val, attach_resp = self._make_rest_call_helper(action_result, attach_endpoint)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            ret_val = self._extract_attachments(
                config, attach_endpoint, attachment_artifacts,
                action_result, attach_resp.get('value', []), container_id, first_time=True
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        artifacts = attachment_artifacts + email_artifacts
        ret_val, message, container_id = self.save_artifacts(artifacts)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, message)

        return phantom.APP_SUCCESS

    def _remove_tokens(self, action_result):
        # checks whether the message includes any of the known error codes
        if len(list(filter(lambda x: x in action_result.get_message(), MSGOFFICE365_ASSET_PARAM_CHECK_LIST_ERRORS))) > 0:
            if not self._admin_access:
                if self._state.get('non_admin_auth', {}).get('access_token'):
                    self._state['non_admin_auth'].pop('access_token')
                if self._state.get('non_admin_auth', {}).get('refresh_token'):
                    self._state['non_admin_auth'].pop('refresh_token')
            else:
                if self._state.get('admin_auth', {}).get('access_token'):
                    self._state['admin_auth'].pop('access_token')

    def _handle_test_connectivity(self, param):
        """ Function that handles the test connectivity action, it is much simpler than other action handlers."""

        action_result = self.add_action_result(ActionResult(param))

        if not self._admin_access or not self._admin_consent:

            self.save_progress("Getting App REST endpoint URL")

            # Get the URL to the app's REST Endpoint, this is the url that the TC dialog
            # box will ask the user to connect to
            ret_val, app_rest_url = self._get_url_to_app_rest(action_result)
            app_state = {}
            if phantom.is_fail(ret_val):
                self.save_progress("Unable to get the URL to the app's REST Endpoint. Error: {0}".format(
                    action_result.get_message()))
                return action_result.set_status(phantom.APP_ERROR)

            # create the url that the oauth server should re-direct to after the auth is completed
            # (success and failure), this is added to the state so that the request handler will access
            # it later on
            redirect_uri = "{0}/result".format(app_rest_url)
            app_state['redirect_uri'] = redirect_uri

            self.save_progress("Using OAuth Redirect URL as:")
            self.save_progress(redirect_uri)

            if self._admin_access:
                # Create the url for fetching administrator consent
                admin_consent_url = "https://login.microsoftonline.com/{0}/adminconsent".format(self._tenant)
                admin_consent_url += "?client_id={0}".format(self._client_id)
                admin_consent_url += "&redirect_uri={0}".format(redirect_uri)
                admin_consent_url += "&state={0}".format(self._asset_id)
            else:
                # Scope is required for non-admin access
                if not self._scope:
                    return action_result.set_status(phantom.APP_ERROR, "Please provide scope for non-admin access in the asset configuration")
                # Create the url authorization, this is the one pointing to the oauth server side
                admin_consent_url = "https://login.microsoftonline.com/{0}/oauth2/v2.0/authorize".format(self._tenant)
                admin_consent_url += "?client_id={0}".format(self._client_id)
                admin_consent_url += "&redirect_uri={0}".format(redirect_uri)
                admin_consent_url += "&state={0}".format(self._asset_id)
                admin_consent_url += "&scope={0}".format(self._scope)
                admin_consent_url += "&response_type=code"

            app_state['admin_consent_url'] = admin_consent_url

            # The URL that the user should open in a different tab.
            # This is pointing to a REST endpoint that points to the app
            url_to_show = "{0}/start_oauth?asset_id={1}&".format(app_rest_url, self._asset_id)

            # Save the state, will be used by the request handler
            _save_app_state(app_state, self._asset_id, self)

            self.save_progress('Please connect to the following URL from a different tab to continue the connectivity process')
            self.save_progress(url_to_show)
            self.save_progress(MSGOFFICE365_AUTHORIZE_TROUBLESHOOT_MSG)

            time.sleep(5)

            completed = False

            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = "{0}/{1}_{2}".format(app_dir, self._asset_id, TC_FILE)

            if self._admin_access:
                self.save_progress('Waiting for Admin Consent to complete')
            else:
                self.save_progress('Waiting for Authorization to complete')

            for i in range(0, 40):

                self.send_progress('{0}'.format('.' * (i % 10)))

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
                    if not self._state.get('admin_consent'):
                        self.save_progress("Admin Consent not received or not given")
                        self.save_progress("Test Connectivity Failed")
                        return action_result.set_status(phantom.APP_ERROR)
                else:
                    if not self._state.get('code'):
                        self.save_progress("Authorization code not received or not given")
                        self.save_progress("Test Connectivity Failed")
                        return action_result.set_status(phantom.APP_ERROR)

        self.save_progress("Getting the token")
        ret_val = self._get_token(action_result)

        if phantom.is_fail(ret_val):
            self._remove_tokens(action_result)
            return action_result.get_status()

        params = {'$top': '1'}
        msg_failed = ""
        if self._admin_access:
            msg_failed = "API to fetch details of all the users failed"
            self.save_progress("Getting info about all users to verify token")
            ret_val, response = self._make_rest_call_helper(action_result, "/users", params=params)
        else:
            msg_failed = "API to get user details failed"
            self.save_progress("Getting info about a single user to verify token")
            ret_val, response = self._make_rest_call_helper(action_result, "/me", params=params)

        if phantom.is_fail(ret_val):
            self.save_progress(msg_failed)
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR)

        value = response.get('value')

        if value:
            self.save_progress("Got user info")

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_copy_email(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param['email_address']
        folder = param["folder"]
        message_id = param['id']
        endpoint = '/users/{0}'.format(email_addr)

        endpoint += '/messages/{0}/copy'.format(message_id)

        body = {'DestinationId': folder}

        if param.get('get_folder_id', True):
            try:
                dir_id, error, _ = self._get_folder_id(action_result, folder, email_addr)
            except ReturnException:
                return action_result.get_status()

            if dir_id:
                body['DestinationId'] = dir_id
            else:
                self.save_progress(error)
                return action_result.set_status(phantom.APP_ERROR, error)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, data=json.dumps(body), method='post')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully copied email")

    def _handle_move_email(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param['email_address']
        folder = param["folder"]
        message_id = param['id']
        endpoint = '/users/{0}'.format(email_addr)

        endpoint += '/messages/{0}/move'.format(message_id)

        body = {'DestinationId': folder}
        if param.get('get_folder_id', True):
            try:
                dir_id, error, _ = self._get_folder_id(action_result, folder, email_addr)

            except ReturnException:
                return action_result.get_status()

            if dir_id:
                body['DestinationId'] = dir_id

            else:
                self.save_progress(error)
                return action_result.set_status(phantom.APP_ERROR, error)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, data=json.dumps(body), method='post')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully moved email")

    def _handle_delete_email(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param['email_address']
        message_id = param['id']
        endpoint = "/users/{0}".format(email_addr)

        endpoint += '/messages/{0}'.format(message_id)

        ret_val, _ = self._make_rest_call_helper(action_result, endpoint, method='delete')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted email")

    def _handle_delete_event(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param['email_address']
        message_id = param['id']
        send_decline_response = param.get('send_decline_response')
        endpoint = "/users/{0}/events/{1}".format(email_addr, message_id)
        method = "delete"
        data = None
        if send_decline_response:
            method = "post"
            endpoint += '/decline'
            data = json.dumps({'sendResponse': True})

        ret_val, _ = self._make_rest_call_helper(action_result, endpoint, method=method, data=data)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted event")

    def _handle_oof_check(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']

        endpoint = '/users/{0}/mailboxSettings/automaticRepliesSetting'.format(user_id)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, method='get')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        action_result.update_summary({'events_matched': action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved out of office status")

    def _handle_list_events(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param.get('user_id') if param.get('user_id') else None
        group_id = param.get('group_id') if param.get('group_id') else None
        query = param.get('filter') if param.get('filter') else None
        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if user_id is None and group_id is None:
            return action_result.set_status(phantom.APP_ERROR, 'Either a "user_id" or "group_id" must be supplied to the "list_events" action')

        if user_id and group_id and user_id != "" and group_id != "":
            return action_result.set_status(phantom.APP_ERROR,
                                            'Either a user_id or group_id can be supplied to the "list_events" action - not both')

        endpoint = ''

        if user_id:
            endpoint = '/users/{0}/calendar/events'.format(user_id)
        else:
            endpoint = '/groups/{0}/calendar/events'.format(group_id)

        if query:
            endpoint = "{0}?{1}".format(endpoint, query)

        ret_val, events = self._paginator(action_result, endpoint, limit)

        if phantom.is_fail(ret_val):
            msg = action_result.get_message()
            if '$top' in msg or '$top/top' in msg:
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
        action_result.update_summary({'events_matched': action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved {} event{}'.format(
            num_events, '' if num_events == 1 else 's'))

    def _handle_list_groups(self, param):

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        query = param.get('filter') if param.get('filter') else None

        endpoint = '/groups'

        ret_val, groups = self._paginator(action_result, endpoint, limit, query=query)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not groups:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for group in groups:
            action_result.add_data(group)

        num_groups = len(groups)
        action_result.update_summary({'total_groups_returned': num_groups})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved {} group{}'.format(
            num_groups, '' if num_groups == 1 else 's'))

    def _handle_list_group_members_by_id(self, param):

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        query = param.get('filter') if param.get('filter') else None
        group_id = param['group_id']
        transitive_members = param.get('get_transitive_members', True)
        endpoint = '/groups/{0}/members'.format(group_id)
        if transitive_members:
            endpoint = '/groups/{0}/transitiveMembers'.format(group_id)

        ret_val, members = self._paginator(action_result, endpoint, limit, query=query)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not members:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for member in members:
            action_result.add_data(member)

        num_members = len(members)
        action_result.update_summary({'total_members_returned': num_members})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved {} group member{}'.format(
            num_members, '' if num_members == 1 else 's'))

    def _handle_list_group_members_by_email(self, param):
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        query = param.get('filter') if param.get('filter') else None
        group_email = param.get['group_email']

        endpoint = "/groups?$filter=displayName eq '{0}'&$select=id".format(group_email)
        ret_val, group_query = self._paginator(action_result, endpoint, limit, query=query)

        try:
            group_id = group_query[0]['id']
        except (IndexError, KeyError):
            return action_result.set_status(phantom.APP_ERROR, "There is no such {} e-mail address in your groups list, please check correctness of the e-mail address".format(group_email))
        except:
            import traceback
            return action_result.set_status(phantom.APP_ERROR, "Occured unexpected problem: {}".format(traceback.format_exc()))

        transitive_members = param.get('get_transitive_members', True)
        endpoint = '/groups/{0}/members'.format(group_id)
        if transitive_members:
            endpoint = '/groups/{0}/transitiveMembers'.format(group_id)

        ret_val, members = self._paginator(action_result, endpoint, limit, query=query)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not members:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for member in members:
            action_result.add_data(member)

        num_members = len(members)
        action_result.update_summary({'total_members_returned': num_members})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved {} group member{}'.format(
            num_members, '' if num_members == 1 else 's'))

    def _handle_list_users(self, param):

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        query = param.get('filter') if param.get('filter') else None

        endpoint = '/users'

        ret_val, users = self._paginator(action_result, endpoint, limit, query=query)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not users:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        for user in users:
            action_result.add_data(user)

        num_users = len(users)
        action_result.update_summary({'total_users_returned': num_users})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved {} user{}'.format(num_users, '' if num_users == 1 else 's'))

    def _handle_list_folders(self, param):

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_folder = list()
        user_id = param['user_id']
        folder_id = param.get('folder_id')

        if not folder_id:
            # fetching root level folders
            ret_val, root_folders = self._fetch_root_folders(action_result, user_id)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # adding root folders to main list of folders
            list_folder.extend(root_folders)

            # checking for child folder if have, add it in list of folders
            for root_folder in root_folders:

                if root_folder.get('childFolderCount', 0) == 0:
                    continue
                else:
                    ret_val = self._list_child_folders(action_result, list_folder, user_id=user_id, parent_folder=root_folder)

                    if phantom.is_fail(ret_val):
                        return action_result.get_status()
        else:
            ret_val = self._list_child_folders(action_result, list_folder, user_id=user_id, folder_id=folder_id)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        for folder in list_folder:
            action_result.add_data(folder)

        num_folders = len(list_folder)
        action_result.update_summary({'total_folders_returned': num_folders})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved {} mail folder{}'.format(
            num_folders, '' if num_folders == 1 else 's'))

    def _fetch_root_folders(self, action_result, user_id):

        endpoint = "/users/{user_id}/mailFolders".format(user_id=user_id)

        ret_val, folders = self._paginator(action_result, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        if not folders:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND), None

        return phantom.APP_SUCCESS, folders

    def _list_child_folders(self, action_result, list_folder, user_id, parent_folder=None, folder_id=None):

        # fetching root level folders
        if not folder_id:
            ret_val, child_folders = self._fetch_child_folders(action_result, user_id, parent_folder['id'])
        else:
            ret_val, child_folders = self._fetch_child_folders(action_result, user_id, folder_id)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # checking for child folder if have, add it in list of folders
        for child_folder in child_folders:

            if child_folder.get('childFolderCount', 0) == 0:
                list_folder.append(child_folder)
            else:
                ret_val = self._list_child_folders(action_result, list_folder, user_id=user_id, parent_folder=child_folder)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                list_folder.append(child_folder)

        return phantom.APP_SUCCESS

    def _fetch_child_folders(self, action_result, user_id, folder_id):

        endpoint = '/users/{user_id}/mailFolders/{folder_id}/childFolders'.format(user_id=user_id, folder_id=folder_id)

        ret_val, folders = self._paginator(action_result, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, folders

    def _flatten_headers(self, headers):

        new_headers = {}
        if not headers:
            return new_headers

        for field in headers:

            if field['name'] == 'Received':
                if 'Received' not in new_headers:
                    new_headers['Received'] = []
                new_headers['Received'].append(field['value'])
                continue

            new_headers[field['name']] = field['value']

        return new_headers

    def _handle_get_email(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param['email_address']
        message_id = param['id']
        endpoint = '/users/{0}'.format(email_addr)

        endpoint += '/messages/{0}'.format(message_id)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if param.get('extract_headers'):
            header_endpoint = endpoint + '?$select=internetMessageHeaders'
            ret_val, header_response = self._make_rest_call_helper(action_result, header_endpoint)

            if phantom.is_fail(ret_val):
                return action_result.get_status()
            # For Drafts there might not be any internetMessageHeaders,
            # so we have to use get() fetching instead of directly fetching from dictionary
            response['internetMessageHeaders'] = header_response.get('internetMessageHeaders')

        if param.get('download_attachments', False) and response.get('hasAttachments'):
            endpoint += '/attachments'
            attachment_endpoint = '{}?$expand=microsoft.graph.itemattachment/item'.format(endpoint)
            ret_val, attach_resp = self._make_rest_call_helper(action_result, attachment_endpoint)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            for attachment in attach_resp.get('value', []):
                # If it is fileAttachment, then we have to ingest it
                if attachment.get("@odata.type") == "#microsoft.graph.fileAttachment":
                    if not self._handle_attachment(attachment, self.get_container_id()):
                        return action_result.set_status(phantom.APP_ERROR, 'Could not process attachment. See logs for details')
                elif attachment.get("@odata.type") == "#microsoft.graph.itemAttachment":
                    if not self._handle_item_attachment(attachment, self.get_container_id(), endpoint, action_result):
                        return action_result.set_status(phantom.APP_ERROR, 'Could not process item attachment. See logs for details')

            response['attachments'] = attach_resp['value']

        if response.get('@odata.type') in ["#microsoft.graph.eventMessage", "#microsoft.graph.eventMessageRequest",
                "#microsoft.graph.eventMessageResponse"]:

            event_endpoint = '{}/?$expand=Microsoft.Graph.EventMessage/Event'.format(endpoint)
            ret_val, event_resp = self._make_rest_call_helper(action_result, event_endpoint)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            response['event'] = event_resp['event']

        if 'internetMessageHeaders' in response:
            response['internetMessageHeaders'] = self._flatten_headers(response['internetMessageHeaders'])

        # If the response has attachments, update every attachment data with its type
        # 'attachmentType' key - indicates type of attachment
        # and if an email has any itemAttachment, then also add itemType in the response
        # 'itemType' key - indicates type of itemAttachment
        if response.get('attachments', []):
            for attachment in response['attachments']:
                attachment_type = attachment.get('@odata.type', '')
                attachment['attachmentType'] = attachment_type
                if attachment_type == '#microsoft.graph.itemAttachment':
                    attachment['itemType'] = attachment.get('item', {}).get('@odata.type', '')

        if param.get('download_email'):
            subject = response.get('subject')
            email_message = {'id': message_id, 'name': subject if subject else "email_message_{}".format(message_id)}
            if not self._handle_item_attachment(email_message, self.get_container_id(), '/users/{0}/messages'.format(email_addr), action_result):
                return action_result.set_status(phantom.APP_ERROR, 'Could not download the email. See logs for details')
            response['vaultId'] = email_message['vaultId']

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched email")

    def _handle_get_email_properties(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        email_addr = param['email_address']
        message_id = param['id']
        endpoint = '/users/{0}'.format(email_addr)

        endpoint += '/messages/{0}'.format(message_id)

        select_list = []
        if param.get('get_headers'):
            select_list.append('internetMessageHeaders')
        if param.get('get_body'):
            select_list.append('body')
        if param.get('get_unique_body'):
            select_list.append('uniqueBody')
        if param.get('get_sender'):
            select_list.append('sender')
        if 'properties_list' in param:
            properties_list = param['properties_list']
            properties_list = [property.strip() for property in properties_list.strip().split(',') if property.strip()]
            select_list += properties_list

        if select_list:
            endpoint += '?$select={0}'.format(','.join(select_list))

        ret_val, response = self._make_rest_call_helper(action_result, endpoint)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if 'internetMessageHeaders' in response:
            response['internetMessageHeaders'] = self._flatten_headers(response['internetMessageHeaders'])

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
        last_modified_time = emails[-1]['lastModifiedDateTime']

        # Calculate the duplicate emails count we can get in the next cycle
        for email in reversed(emails):
            if email["lastModifiedDateTime"] != last_modified_time:
                break
            expected_duplicate_count_in_next_cycle += 1

        limit = expected_duplicate_count_in_next_cycle + remaining_count
        return limit, total_ingested

    def _handle_on_poll(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        ingest_manner = config.get('ingest_manner', 'oldest first')

        start_time = ''
        if self.is_poll_now():
            max_emails = param[phantom.APP_JSON_CONTAINER_COUNT]
        elif self._state.get('first_run', True):
            # Integer validation for 'first_run_max_emails' config parameter
            ret_val, max_emails = _validate_integer(
                action_result, config.get('first_run_max_emails', 1000), "'Maximum Containers for scheduled polling first time' config"
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        else:
            # Integer validation for 'max_containers' config parameter
            ret_val, max_emails = _validate_integer(
                action_result, config.get('max_containers', 100), "'Maximum Containers for scheduled polling' config"
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            start_time = self._state['last_time']

        if not config.get('email_address'):
            return action_result.set_status(phantom.APP_ERROR, "Email Address to ingest must be supplied in asset!")
        elif not config.get('folder'):
            return action_result.set_status(phantom.APP_ERROR, "Folder to ingest from must be supplied in asset!")

        endpoint = "/users/{0}".format(config.get('email_address'))

        if 'folder' in config:
            folder = config.get('folder', '')
            if config.get('get_folder_id', True):
                try:
                    dir_id, error, _ = self._get_folder_id(action_result, folder, config.get('email_address'))
                except ReturnException:
                    return action_result.get_status()
                if dir_id:
                    folder = dir_id
                else:
                    self.save_progress(error)
                    return action_result.set_status(phantom.APP_ERROR, error)
            endpoint += '/mailFolders/{0}'.format(folder)

        endpoint += '/messages'
        order = 'asc' if ingest_manner == 'oldest first' else 'desc'

        params = {
            '$orderBy': 'lastModifiedDateTime {}'.format(order)
        }

        if start_time:
            params['$filter'] = "lastModifiedDateTime ge {0}".format(start_time)

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
                    self.send_progress('Processing email # {} with ID ending in: {}'.format(index + 1, email['id'][-10:]))
                    ret_val = self._process_email_data(config, action_result, endpoint, email)
                    if phantom.is_fail(ret_val):
                        failed_email_ids += 1
                        self.debug_print(f"Error occurred while processing email ID: {email.get('id')}. {action_result.get_message()}")
                except Exception as e:
                    failed_email_ids += 1
                    error_msg = _get_error_message_from_exception(e)
                    self.debug_print(f"Exception occurred while processing email ID: {email.get('id')}. {error_msg}")

            if failed_email_ids == total_emails:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing all the email IDs")

            if not self.is_poll_now():
                last_time = datetime.strptime(emails[email_index]['lastModifiedDateTime'], O365_TIME_FORMAT).strftime(O365_TIME_FORMAT)
                self._state['last_time'] = last_time
                self.save_state(deepcopy(self._state))

                # Setting filter for next cycle
                params['$filter'] = "lastModifiedDateTime ge {0}".format(last_time)

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
        if not self.is_poll_now() and self._state.get('first_run', True):
            self._state['first_run'] = False

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_range(self, email_range, action_result):

        try:
            mini, maxi = (int(x) for x in email_range.split('-'))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse the range. Please specify the range as min_offset-max_offset")

        if mini < 0 or maxi < 0:
            return action_result.set_status(phantom.APP_ERROR, "Invalid min or max offset value specified in range", )

        if mini > maxi:
            return action_result.set_status(phantom.APP_ERROR, "Invalid range value, min_offset greater than max_offset")

        if maxi > MAX_END_OFFSET_VAL:
            return action_result.set_status(phantom.APP_ERROR, "Invalid range value. The max_offset value cannot be greater than {0}".format(
                MAX_END_OFFSET_VAL))

        return (phantom.APP_SUCCESS)

    def _handle_generate_token(self, param):

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._get_token(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state['admin_consent'] = True

        return action_result.set_status(phantom.APP_SUCCESS, "Token generated")

    def _handle_run_query(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')
        # Integer validation for 'limit' action parameter
        ret_val, limit = _validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # user
        email_addr = param['email_address']
        endpoint = "/users/{0}".format(email_addr)
        query = ""
        params = dict()

        if 'internet_message_id' in param:
            params = {
                '$filter': "internetMessageId eq '{0}'".format(param['internet_message_id'])
            }

        elif 'query' in param:
            query = "?{0}".format(param['query'])

        else:
            # search params
            search_query = ''
            if 'subject' in param:
                search_query += "subject:{0} ".format(param['subject'])

            if 'body' in param:
                search_query += "body:{0} ".format(param['body'])

            if 'sender' in param:
                search_query += "from:{0} ".format(param['sender'])

            if search_query:
                params['$search'] = '"{0}"'.format(search_query[:-1])

        folder_ids = []
        # searches through well known folders
        if param.get('search_well_known_folders', False):

            endpoint += "/mailFolders"
            folder_params = {
                '$filter': "{}".format(MSGOFFICE365_WELL_KNOWN_FOLDERS_FILTER)
            }
            ret_val, response = self._paginator(action_result, endpoint, params=folder_params)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR)

            if not response:
                return action_result.set_status(phantom.APP_SUCCESS, "No well known folders found")

            folders = response

            for folder in folders:
                folder_ids.append(folder.get('id'))

            endpoint += "/{folder_id}"

        # folder
        elif 'folder' in param:

            folder = param['folder']

            if param.get('get_folder_id', True):
                try:
                    dir_id, error, _ = self._get_folder_id(action_result, folder, email_addr)
                except ReturnException:
                    return action_result.get_status()
                if dir_id:
                    folder = dir_id
                else:
                    self.save_progress(error)
                    return action_result.set_status(phantom.APP_ERROR, error)
            folder_ids.append(folder)
            endpoint += '/mailFolders/{folder_id}'

        # that should be enough to create the endpoint
        endpoint += '/messages'

        if folder_ids:
            messages = []
            ret_val = False
            for folder_id in folder_ids:
                folder_ret_val, folder_messages = self._paginator(action_result, endpoint.format(
                    folder_id=folder_id) + query, limit, params=params)

                if phantom.is_fail(folder_ret_val):
                    continue

                ret_val = True
                messages.extend(folder_messages)

        else:
            ret_val, messages = self._paginator(action_result, endpoint, limit, params=params)

        if phantom.is_fail(ret_val):
            msg = action_result.get_message()
            if '$top' in msg or '$top/top' in msg:
                msg += "The '$top' parameter is already used internally to handle pagination logic. "
                msg += "If you want to restrict results in terms of number of output results, you can use the 'limit' parameter."
                return action_result.set_status(phantom.APP_ERROR, msg)
            return action_result.get_status()

        if not messages:
            return action_result.set_status(phantom.APP_SUCCESS, MSGOFFICE365_NO_DATA_FOUND)

        action_result.update_data(messages)
        action_result.update_summary({'emails_matched': action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_folder_id(self, action_result, folder, email):
        # hindsight is always 20-20, set the folder path separator to be '/', thinking folder names allow '\' as a char.
        # turns out even '/' is supported by office365, so let the action escape the '/' char if it's part of the folder name
        folder_path = folder.replace('\\/', self._REPLACE_CONST)
        folder_names = folder_path.split('/')
        for i, folder_name in enumerate(folder_names):
            folder_names[i] = folder_name.replace(self._REPLACE_CONST, '/').strip()

        # remove empty elements
        path = list(filter(None, folder_names))

        ret = list()
        try:
            dir_id = self._get_folder(action_result, path[0], email)
        except ReturnException as e:
            return None, "Error occurred while fetching folder {}. {}".format(path[0], e), None

        if not dir_id:
            return None, "Error: folder not found; {}".format(path[0]), ret

        ret.append({"path": path[0], "folder": path[0], "folder_id": dir_id})

        try:
            for i, subf in enumerate(path[1:]):
                subpath = "/".join(path[0:i + 2])
                parent_id = dir_id
                dir_id = self._get_child_folder(action_result, subf, parent_id, email)

                if not dir_id:
                    return None, "Error: child folder not found; {}".format(subpath), ret

                ret.append({"path": subpath, "folder": subf, "folder_id": dir_id})
        except ReturnException:
            return None, action_result.get_message(), None

        return dir_id, None, ret

    def _get_folder(self, action_result, folder, email):

        params = {}
        params['$filter'] = "displayName eq '{}'".format(folder)
        endpoint = "/users/{}/mailFolders".format(email)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params)

        if phantom.is_fail(ret_val):
            raise ReturnException(action_result.get_message())

        value = response.get('value', [])
        if len(value) > 0:
            self._currentdir = value[0]
            return value[0]['id']

        return None

    def _get_child_folder(self, action_result, folder, parent_id, email):

        params = {}
        params['$filter'] = "displayName eq '{}'".format(folder)
        endpoint = "/users/{}/mailFolders/{}/childFolders".format(email, parent_id)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params)

        if phantom.is_fail(ret_val):
            raise ReturnException()

        value = response.get('value', [])
        if len(value) > 0:
            self._currentdir = value[0]
            return value[0]['id']

        return None

    def _new_folder(self, action_result, folder, email):

        data = json.dumps({"displayName": folder})
        endpoint = "/users/{}/mailFolders".format(email)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, data=data, method="post")
        if phantom.is_fail(ret_val):
            raise ReturnException()

        if response.get('id', False):
            self._currentdir = response
            self.save_progress("Success({}): created folder in mailbox".format(folder))
            return response['id']

        msg = "Error({}): unable to create folder in mailbox".format(folder)
        self.save_progress(msg)
        action_result.set_status(phantom.APP_ERROR, msg)
        raise ReturnException()

    def _new_child_folder(self, action_result, folder, parent_id, email, pathsofar):

        data = json.dumps({"displayName": folder})
        endpoint = "/users/{}/mailFolders/{}/childFolders".format(email, parent_id)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, data=data, method="post")
        if phantom.is_fail(ret_val):
            raise ReturnException()

        if response.get('id', False):
            self._currentdir = response
            self.save_progress("Success({}): created child folder in folder {}".format(folder, pathsofar))
            return response['id']

        msg = "Error({}): unable to create child folder in folder {}".format(folder, pathsofar)
        self.save_progress(msg)
        action_result.set_status(phantom.APP_ERROR, msg)
        raise ReturnException()

    def _handle_create_folder(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        email = param["email_address"]
        folder = param["folder"]

        minusp = param.get("all_subdirs", False)

        # hindsight is always 20-20, set the folder path separator to be '/', thinking folder names allow '\' as a char.
        # turns out even '/' is supported by office365, so let the action escape the '/' char if it's part of the folder name
        folder_path = folder.replace('\\/', self._REPLACE_CONST)
        folder_names = folder_path.split('/')
        for i, folder_name in enumerate(folder_names):
            folder_names[i] = folder_name.replace(self._REPLACE_CONST, '/').strip()

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
                    msg = "Error({}): folder already exists in mailbox".format(path[0])
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
                        msg = "Error({}): folder doesn't exists in mailbox".format(path[0])
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
                            msg = "Error({}): child folder doesn't exists in folder {}".format(subf, pathsofar)
                            self.save_progress(msg)
                            return action_result.set_status(phantom.APP_ERROR, msg)

                    pathsofar += "/" + subf
                    parent_id = dir_id

                # finally, the actual folder
                dir_id = self._get_child_folder(action_result, final, parent_id, email)
                if dir_id:
                    msg = "Error: child folder {0} already exists in the folder {1}".format(final, pathsofar)
                    self.save_progress(msg)
                    return action_result.set_status(phantom.APP_ERROR, msg)

                dir_id = self._new_child_folder(action_result, final, parent_id, email, pathsofar)
                action_result.add_data(self._currentdir)

        except ReturnException:
            return action_result.get_status()

        action_result.update_summary({"folders created": len(action_result.get_data()), "folder": self._currentdir['id']})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_folder_id(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        email = param["email_address"]
        folder = param["folder"]

        try:
            dir_id, error, ret = self._get_folder_id(action_result, folder, email)

        except ReturnException:
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

    def _paginator(self, action_result, endpoint, limit=None, params=None, query=None):
        """
        This action is used to create an iterator that will paginate through responses from called methods.

        :param method_name: Name of method whose response is to be paginated
        :param action_result: Object of ActionResult class
        :param **kwargs: Dictionary of Input parameters
        """

        list_items = list()
        next_link = None

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

        while True:
            if next_link:
                ret_val, response = self._make_rest_call_helper(action_result, endpoint, nextLink=next_link, params=params)
            else:
                ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            if response.get("value"):
                list_items.extend(response.get("value"))

            if limit and len(list_items) >= limit:
                return phantom.APP_SUCCESS, list_items[:limit]

            next_link = response.get('@odata.nextLink')
            if not next_link:
                break

            params = None

        return phantom.APP_SUCCESS, list_items

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'copy_email':
            ret_val = self._handle_copy_email(param)

        elif action_id == 'move_email':
            ret_val = self._handle_move_email(param)

        elif action_id == 'delete_email':
            ret_val = self._handle_delete_email(param)

        elif action_id == 'delete_event':
            ret_val = self._handle_delete_event(param)

        elif action_id == 'get_email':
            ret_val = self._handle_get_email(param)

        elif action_id == 'get_email_properties':
            ret_val = self._handle_get_email_properties(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        elif action_id == 'run_query':
            ret_val = self._handle_run_query(param)

        elif action_id == 'list_events':
            ret_val = self._handle_list_events(param)

        elif action_id == 'list_groups':
            ret_val = self._handle_list_groups(param)

        elif action_id == 'list_group_members_by_id':
            ret_val = self._handle_list_group_members_by_id(param)
        
        elif action_id == 'list_group_members_by_email':
            ret_val = self._handle_list_group_members_by_email(param)

        elif action_id == 'list_users':
            ret_val = self._handle_list_users(param)

        elif action_id == 'list_folders':
            ret_val = self._handle_list_folders(param)

        elif action_id == 'oof_check':
            ret_val = self._handle_oof_check(param)

        elif action_id == 'generate_token':
            ret_val = self._handle_generate_token(param)

        elif action_id == 'create_folder':
            ret_val = self._handle_create_folder(param)

        elif action_id == 'get_folder_id':
            ret_val = self._handle_get_folder_id(param)

        return ret_val

    def _get_token(self, action_result):

        req_url = SERVER_TOKEN_URL.format(self._tenant)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': 'client_credentials'
        }

        if not self._admin_access:
            data['scope'] = 'offline_access ' + self._scope
        else:
            data['scope'] = 'https://graph.microsoft.com/.default'

        if not self._admin_access:
            if self._refresh_token:
                data['refresh_token'] = self._refresh_token
                data['grant_type'] = 'refresh_token'
            elif self._state.get('code'):
                data['redirect_uri'] = self._state.get('redirect_uri')
                data['code'] = self._state.get('code')
                data['grant_type'] = 'authorization_code'
            else:
                return action_result.set_status(phantom.APP_ERROR, "Unexpected details retrieved from the state file.")

        self.debug_print("Generating token...")
        ret_val, resp_json = self._make_rest_call(action_result, req_url, headers=headers, data=data, method='post')
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        # Save the response on the basis of admin_access
        if self._admin_access:
            # if admin consent already provided, save to state
            if self._admin_consent:
                self._state['admin_consent'] = True
            self._state['admin_auth'] = resp_json
        else:
            self._state['non_admin_auth'] = resp_json
        # Fetching the access token and refresh token
        self._access_token = resp_json.get('access_token')
        self._refresh_token = resp_json.get('refresh_token')

        # Save state
        self.save_state(self._state)
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print(MSGOFFICE365_STATE_FILE_CORRUPT_ERR)
            self._reset_state_file()
            return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_STATE_FILE_CORRUPT_ERR)

        # Scenario -
        #
        # If the corresponding state file doesn't have correct owner, owner group or permissions,
        # the newly generated token is not being saved to state file and automatic workflow for token has been stopped.
        # So we have to check that token from response and token which are saved to state file
        # after successful generation of new token are same or not.

        if self._admin_access:
            if self._access_token != self._state.get('admin_auth', {}).get('access_token'):
                return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_INVALID_PERMISSION_ERR)
        else:
            if self._access_token != self._state.get('non_admin_auth', {}).get('access_token'):
                return action_result.set_status(phantom.APP_ERROR, MSGOFFICE365_INVALID_PERMISSION_ERR)
        self.debug_print("Token generated successfully")
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

        # Load all the asset configuration in global variables
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print(MSGOFFICE365_STATE_FILE_CORRUPT_ERR)
            self._reset_state_file()
            return self.set_status(phantom.APP_ERROR, MSGOFFICE365_STATE_FILE_CORRUPT_ERR)

        self._tenant = config['tenant']
        self._client_id = config['client_id']
        self._client_secret = config['client_secret']
        self._admin_access = config.get('admin_access')
        self._admin_consent = config.get('admin_consent')
        self._scope = config.get('scope') if config.get('scope') else None

        self._number_of_retries = config.get("retry_count", MSGOFFICE365_DEFAULT_NUMBER_OF_RETRIES)
        ret_val, self._number_of_retries = _validate_integer(self, self._number_of_retries,
                "'Maximum attempts to retry the API call' asset configuration")
        if phantom.is_fail(ret_val):
            return self.get_status()

        self._retry_wait_time = config.get("retry_wait_time", MSGOFFICE365_DEFAULT_RETRY_WAIT_TIME)
        ret_val, self._retry_wait_time = _validate_integer(self, self._retry_wait_time,
                "'Delay in seconds between retries' asset configuration")
        if phantom.is_fail(ret_val):
            return self.get_status()

        if not self._admin_access:
            if not self._scope:
                return self.set_status(phantom.APP_ERROR, "Please provide scope for non-admin access in the asset configuration")

            self._access_token = self._state.get('non_admin_auth', {}).get('access_token', None)
            self._refresh_token = self._state.get('non_admin_auth', {}).get('refresh_token', None)

        else:
            self._access_token = self._state.get('admin_auth', {}).get('access_token', None)

        if action_id == 'test_connectivity':
            # User is trying to complete the authentication flow, so just return True from here so that test connectivity continues
            return phantom.APP_SUCCESS

        admin_consent = self._state.get('admin_consent')

        # if it was not and the current action is not test connectivity then it's an error
        if self._admin_access:
            if not admin_consent and action_id != 'test_connectivity':
                return self.set_status(phantom.APP_ERROR, MSGOFFICE365_RUN_CONNECTIVITY_MSG)

        if not self._admin_access and action_id != 'test_connectivity' and (not self._access_token or not self._refresh_token):
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return self.set_status(phantom.APP_ERROR, "{0}. {1}".format(MSGOFFICE365_RUN_CONNECTIVITY_MSG, action_result.get_message()))

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
            self.debug_print('FIPS is enabled')
        else:
            self.debug_print('FIPS is not enabled')
        return fips_enabled

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None
    verify = args.verify

    if args.username and args.password:
        login_url = '{}login'.format(BaseConnector._get_phantom_base_url())
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']
            data = {'username': args.username, 'password': args.password, 'csrfmiddlewaretoken': csrftoken}
            headers = {'Cookie': 'csrftoken={0}'.format(csrftoken), 'Referer': login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies['sessionid']

        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
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
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
