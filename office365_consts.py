# File: office365_consts.py
#
# Copyright (c) 2017-2024 Splunk Inc.
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
TC_STATUS_SLEEP = 2
MSGOFFICE365_PER_PAGE_COUNT = 999
MSGOFFICE365_UPLOAD_SESSION_CUTOFF = 3145728  # 3MB
MSGOFFICE365_UPLOAD_LARGE_FILE_CUTOFF = 52428800  # 52MB
SPLUNK_SOAR_SYS_INFO_URL = "{url}rest/system_info"
SPLUNK_SOAR_ASSET_INFO_URL = "{url}rest/asset/{asset_id}"
SPLUNK_SOAR_CONTAINER_INFO_URL = "{url}rest/container/{container_id}"
O365_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MSGOFFICE365_RUN_CONNECTIVITY_MSG = (
    "Please run test connectivity first to complete authorization flow and " "generate a token that the app can use to make calls to the server "
)
MSGOFFICE365_WELL_KNOWN_FOLDERS_FILTER = [
    "archive",
    "clutter",
    "conflicts",
    "conversationhistory",
    "deleteditems",
    "drafts",
    "inbox",
    "junkemail",
    "localfailures",
    "msgfolderroot",
    "outbox",
    "recoverableitemsdeletions",
    "scheduled",
    "searchfolders",
    "sentitems",
    "serverfailures",
    "syncissues",
]
MSGOFFICE365_STATE_FILE_CORRUPT_ERROR = (
    "Error occurred while loading the state file. " "Resetting the state file with the default format. Please test the connectivity."
)

MSGOFFICE365_AUTHORIZE_TROUBLESHOOT_MSG = (
    "If authorization URL fails to communicate with your "
    "Splunk SOAR instance, check whether you have:  "
    " 1. Specified the Web Redirect URL of your App -- The Redirect URL should be <POST URL>/result . "
    " 2. Configured the base URL of your Splunk SOAR Instance at Administration -> Company Settings -> Info"
)
MSGOFFICE365_INVALID_PERMISSION_ERROR = (
    "Error occurred while saving the newly generated access token " "(in place of the expired token) in the state file."
)
MSGOFFICE365_INVALID_PERMISSION_ERROR += " Please check the owner, owner group, and the permissions of the state file. The Splunk SOAR "
MSGOFFICE365_INVALID_PERMISSION_ERROR += (
    "user should have the correct access rights and ownership for the corresponding state file " "(refer to readme file for more information)."
)
MSGOFFICE365_NO_DATA_FOUND = "No data found"
MSGOFFICE365_DUPLICATE_CONTAINER_FOUND_MSG = "duplicate container found"
MSGOFFICE365_ERROR_EMPTY_RESPONSE = "Status Code {code}. Empty response and no information in the header."
MSGOFFICE365_CBA_AUTH_ERROR = "Certificate Based Authentication requires both Certificate Thumbprint and Certificate Private Key"
MSGOFFICE365_OAUTH_AUTH_ERROR = "OAuth Authentication requires Client Secret"
MSGOFFICE365_AUTOMATIC_AUTH_ERROR = (
    "Automatic Authentication requires either Client Secret or combination of Certificate Thumbprint and Certificate Private Key"
)
MSGOFFICE365_CBA_ADMIN_CONSENT_ERROR = "Certificate Based Authorization requires Admin Consent to be Provided"
MSGOFFICE365_CBA_KEY_FILE_ERROR = "Error occurred while reading the private key. {0}"
MSGOFFICE365_NON_ADMIN_SCOPE_ERROR = "Please provide scope for non-admin access in the asset configuration for OAuth authentication"

MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT = 30  # in seconds
MSGOFFICE365_DEFAULT_NUMBER_OF_RETRIES = 3
MSGOFFICE365_DEFAULT_RETRY_WAIT_TIME = 60  # in seconds
MSGOFFICE365_CONTAINER_DESCRIPTION = "Email ingested using MS Graph API - {last_modified_time}"
MSGOFFICE365_HTTP_401_STATUS_CODE = "401"
MSGOFFICE365_INVALID_CLIENT_ID_ERROR_CODE = "AADSTS700016"
MSGOFFICE365_INVALID_TENANT_ID_FORMAT_ERROR_CODE = "AADSTS900023"
MSGOFFICE365_INVALID_TENANT_ID_NOT_FOUND_ERROR_CODE = "AADSTS90002"
MSGOFFICE365_ASSET_PARAM_CHECK_LIST_ERROR = [
    MSGOFFICE365_HTTP_401_STATUS_CODE,
    MSGOFFICE365_INVALID_CLIENT_ID_ERROR_CODE,
    MSGOFFICE365_INVALID_TENANT_ID_FORMAT_ERROR_CODE,
    MSGOFFICE365_INVALID_TENANT_ID_NOT_FOUND_ERROR_CODE,
]

# Constants relating to '_get_error_message_from_exception'

MSGOFFICE365_ERROR_MSG_UNAVAILABLE = "Error msg unavailable. Please check the asset configuration and|or action parameters"

# Constants relating to 'validate_integer'
MSGOFFICE365_VALID_INT_MSG = "Please provide a valid integer value in the {param} parameter"
MSGOFFICE365_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in the {param} parameter"
MSGOFFICE365_AUTH_FAILURE_MSG = [
    "token is invalid",
    "Access token has expired",
    "ExpiredAuthenticationToken",
    "AuthenticationFailed",
    "TokenExpired",
    "InvalidAuthenticationToken",
    "Lifetime validation failed, the token is expired.",
]
MSGOFFICE365_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {param} parameter"
MSGOFFICE365_ENCRYPTION_ERROR = "Error occurred while encrypting the state file"
MSGOFFICE365_DECRYPTION_ERROR = "Error occurred while decrypting the state file"
MSGOFFICE365_UNEXPECTED_ACCESS_TOKEN_ERROR = "Found unexpected value of access token. Please run the test connectivity to generate a new token"
MSGOFFICE365_INVALID_EMAIL = "Please provide a valid email-address in the 'identificator' parameter"
MSGOFFICE365_INVALID_METHOD = "Please provide a valid method in the 'method' parameter"

MSGOFFICE365_SELECT_PARAMETER_LIST = [
    "bccRecipients",
    "body",
    "bodyPreview",
    "categories",
    "ccRecipients",
    "changeKey",
    "conversationId",
    "conversationIndex",
    "createdDateTime",
    "flag",
    "from",
    "hasAttachments",
    "id",
    "importance",
    "inferenceClassification",
    "internetMessageHeaders",
    "isDeliveryReceiptRequested",
    "isDraft",
    "isRead",
    "isReadReceiptRequested",
    "lastModifiedDateTime",
    "parentFolderId",
    "receivedDateTime",
    "replyTo",
    "sender",
    "sentDateTime",
    "subject",
    "toRecipients",
    "uniqueBody",
    "webLink",
    "internetMessageId",
]

MSGOFFICE365_AUTH_TYPES = {"Automatic": "auto", "OAuth": "oauth", "Certificate Based Authentication(CBA)": "cba"}

MSGOFFICE365_AUTH_AUTOMATIC = "Automatic"

MSGOFFICE365_DEFAULT_FOLDER = "Inbox"
MSGOFFICE365_DEFAULT_LIMIT = 100
MSGOFFICE365_ORDERBY_RECEIVED_DESC = "receivedDateTime desc"
MSGOFFICE365_RECEIVED_DATE_FILTER = "receivedDateTime {operator} {date}"
MSGOFFICE365_DATE_FILTER_AND = " and "
