# Copyright (c) 2017-2026 Splunk Inc.
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

import json
import time

import requests
from soar_sdk.abstract import SOARClient
from soar_sdk.logging import getLogger

from .consts import (
    MSGOFFICE365_AUTH_FAILURE_MSG,
    MSGOFFICE365_AUTH_TYPES,
    MSGOFFICE365_AUTHORITY_URL,
    MSGOFFICE365_CBA_KEY_ERROR,
    MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT,
    MSGOFFICE365_DEFAULT_RETRY_WAIT_TIME,
    MSGOFFICE365_DEFAULT_SCOPE,
    MSGOFFICE365_WELL_KNOWN_FOLDERS_FILTER,
    MSGRAPH_API_URL,
    SERVER_TOKEN_URL,
)


logger = getLogger()


class MsGraphHelper:
    def __init__(self, soar: SOARClient, asset):
        self.soar = soar
        self.asset = asset
        self._access_token = None
        self._refresh_token = None
        self._auth_type = MSGOFFICE365_AUTH_TYPES.get(asset.auth_type, "auto")
        self._number_of_retries = asset.retry_count or 3
        self._retry_wait_time = (
            asset.retry_wait_time or MSGOFFICE365_DEFAULT_RETRY_WAIT_TIME
        )

    def _get_auth_state(self) -> dict:
        return dict(self.asset.auth_state.get_all())

    def _save_auth_state(self, state: dict):
        self.asset.auth_state.put_all(state)

    def _generate_cba_access_token(self):
        import msal  # Lazy import due to BOM issue in msal package

        logger.info("Generating token using Certificate Based Authentication...")
        authority = MSGOFFICE365_AUTHORITY_URL.format(tenant=self.asset.tenant)
        try:
            app_client = msal.ConfidentialClientApplication(
                client_id=self.asset.client_id,
                authority=authority,
                client_credential={
                    "thumbprint": self.asset.certificate_thumbprint,
                    "private_key": self.asset.certificate_private_key,
                },
            )
        except ValueError as e:
            if "private_key" in str(e).lower():
                raise Exception(MSGOFFICE365_CBA_KEY_ERROR) from None
            raise

        res_json = app_client.acquire_token_for_client(
            scopes=[MSGOFFICE365_DEFAULT_SCOPE]
        )
        if error := res_json.get("error"):
            error_message = f"{error}: {res_json.get('error_description')}"
            raise Exception(error_message)
        return res_json

    def _generate_oauth_access_token(self):
        logger.info("Generating token using OAuth Authentication...")
        req_url = SERVER_TOKEN_URL.format(self.asset.tenant)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        state = self._get_auth_state()

        data = {
            "client_id": self.asset.client_id,
            "client_secret": self.asset.client_secret,
            "grant_type": "client_credentials",
        }

        if not self.asset.admin_access:
            data["scope"] = "offline_access " + (self.asset.scope or "")
            if state.get("code"):
                data["redirect_uri"] = state.get("redirect_uri")
                data["code"] = state.get("code")
                data["grant_type"] = "authorization_code"
            elif self._refresh_token:
                data["refresh_token"] = self._refresh_token
                data["grant_type"] = "refresh_token"
        else:
            data["scope"] = MSGOFFICE365_DEFAULT_SCOPE

        resp = requests.post(
            req_url,
            headers=headers,
            data=data,
            timeout=MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    def get_token(self):
        state = self._get_auth_state()
        if self.asset.admin_access:
            self._access_token = state.get("admin_auth", {}).get("access_token")
        else:
            self._access_token = state.get("non_admin_auth", {}).get("access_token")
            self._refresh_token = state.get("non_admin_auth", {}).get("refresh_token")

        if self._access_token:
            return

        if self._auth_type == "cba" or not self.asset.client_secret:
            resp_json = self._generate_cba_access_token()
            state["auth_type"] = "cba"
        else:
            resp_json = self._generate_oauth_access_token()
            state["auth_type"] = "oauth"

        if self.asset.admin_access:
            if self.asset.admin_consent:
                state["admin_consent"] = True
            state["admin_auth"] = resp_json
        else:
            state["non_admin_auth"] = resp_json

        self._access_token = resp_json.get("access_token")
        self._refresh_token = resp_json.get("refresh_token")
        self._save_auth_state(state)

    def _make_rest_call(
        self, url, method="get", headers=None, params=None, data=None, download=False
    ):
        if headers is None:
            headers = {}
        headers.update(
            {
                "Authorization": f"Bearer {self._access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        request_func = getattr(requests, method)
        for _ in range(self._number_of_retries):
            resp = request_func(
                url,
                headers=headers,
                params=params,
                data=data,
                timeout=MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT,
            )
            if resp.status_code != 502:
                break
            time.sleep(self._retry_wait_time)

        if download:
            if 200 <= resp.status_code < 399:
                return resp.text
            raise Exception(f"Error downloading: {resp.status_code}")

        if resp.status_code == 204:
            return {}

        if not resp.text:
            if 200 <= resp.status_code < 399:
                return {}
            raise Exception(f"Empty response with status {resp.status_code}")

        if "json" in resp.headers.get("Content-Type", ""):
            resp_json = resp.json()
            if 200 <= resp.status_code < 399:
                return resp_json
            error = resp_json.get("error", {})
            error_msg = (
                error.get("message", resp.text)
                if isinstance(error, dict)
                else str(error)
            )
            raise Exception(f"API Error {resp.status_code}: {error_msg}")

        if resp.status_code >= 400:
            raise Exception(f"Error {resp.status_code}: {resp.text[:500]}")
        return {}

    def make_rest_call_helper(
        self,
        endpoint,
        method="get",
        params=None,
        data=None,
        nextLink=None,
        download=False,
        beta=False,
    ):
        if nextLink:
            url = nextLink
        else:
            api_version = "beta" if beta else "v1.0"
            url = f"{MSGRAPH_API_URL}/{api_version}{endpoint}"

        try:
            return self._make_rest_call(
                url, method=method, params=params, data=data, download=download
            )
        except Exception as e:
            error_msg = str(e)
            if any(msg in error_msg for msg in MSGOFFICE365_AUTH_FAILURE_MSG):
                logger.info("Token expired, refreshing...")
                self._access_token = None
                self.get_token()
                return self._make_rest_call(
                    url, method=method, params=params, data=data, download=download
                )
            raise

    def get_folder_id(self, folder_name: str, email_address: str) -> str | None:
        if not folder_name:
            return None

        if folder_name.lower() in MSGOFFICE365_WELL_KNOWN_FOLDERS_FILTER:
            return folder_name

        folders = folder_name.split("/")
        parent_folder_id = None

        for folder in folders:
            if not folder:
                continue
            if parent_folder_id:
                endpoint = f"/users/{email_address}/mailFolders/{parent_folder_id}/childFolders"
            else:
                endpoint = f"/users/{email_address}/mailFolders"

            params = {"$filter": f"displayName eq '{folder}'"}
            resp = self.make_rest_call_helper(endpoint, params=params)
            value = resp.get("value", [])
            if not value:
                return None
            parent_folder_id = value[0].get("id")

        return parent_folder_id


def serialize_complex_fields(resp: dict, fields: list[str]) -> dict:
    """Serialize complex fields (dict/list) to JSON strings for ActionOutput."""
    for field in fields:
        if field in resp and resp[field] is not None:
            if isinstance(resp[field], (dict, list)):
                resp[field] = json.dumps(resp[field])
    return resp
