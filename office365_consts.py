# File: office365_consts.py
#
# Copyright (c) 2017-2023 Splunk Inc.
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
SPLUNK_SOAR_SYS_INFO_URL = "{url}rest/system_info"
SPLUNK_SOAR_ASSET_INFO_URL = "{url}rest/asset/{asset_id}"
SPLUNK_SOAR_CONTAINER_INFO_URL = "{url}rest/container/{container_id}"
O365_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MSGOFFICE365_RUN_CONNECTIVITY_MESSAGE = "Please run test connectivity first to complete authorization flow and "\
    "generate a token that the app can use to make calls to the server "
MSGOFFICE365_WELL_KNOWN_FOLDERS_FILTER = "displayName eq 'archive' or displayName eq 'clutter' or "\
    "displayName eq 'conflicts' or displayName eq 'conversation history' or displayName eq 'deleted items' or "\
    "displayName eq 'drafts' or displayName eq 'inbox' or displayName eq 'junk email' or displayName eq 'local failures' or"\
    " displayName eq 'msg folder root' or displayName eq 'outbox' or displayName eq 'recoverable items deletions' or "\
    "displayName eq 'scheduled' or displayName eq 'search folders' or displayName eq 'sent items' or displayName eq 'server failures' or "\
    "displayName eq 'sync issues'"
MSGOFFICE365_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file. " \
    "Resetting the state file with the default format. Please test the connectivity."

MSGOFFICE365_AUTHORIZE_TROUBLESHOOT_MESSAGE = 'If authorization URL fails to communicate with your '\
    'Splunk SOAR instance, check whether you have:  '\
    ' 1. Specified the Web Redirect URL of your App -- The Redirect URL should be <POST URL>/result . '\
    ' 2. Configured the base URL of your Splunk SOAR Instance at Administration -> Company Settings -> Info'
MSGOFFICE365_INVALID_PERMISSION_ERROR = "Error occurred while saving the newly generated access token "\
    "(in place of the expired token) in the state file."
MSGOFFICE365_INVALID_PERMISSION_ERROR += " Please check the owner, owner group, and the permissions of the state file. The Splunk SOAR "
MSGOFFICE365_INVALID_PERMISSION_ERROR += "user should have the correct access rights and ownership for the corresponding state file "\
    "(refer to readme file for more information)."
MSGOFFICE365_NO_DATA_FOUND = "No data found"

MSGOFFICE365_DUPLICATE_CONTAINER_FOUND_MESSAGE = "duplicate container found"
MSGOFFICE365_ERROR_EMPTY_RESPONSE = "Status Code {code}. Empty response and no information in the header."

MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT = 30  # in seconds
MSGOFFICE365_DEFAULT_NUMBER_OF_RETRIES = 3
MSGOFFICE365_DEFAULT_RETRY_WAIT_TIME = 60  # in seconds
MSGOFFICE365_CONTAINER_DESCRIPTION = 'Email ingested using MS Graph API - {last_modified_time}'
MSGOFFICE365_HTTP_401_STATUS_CODE = '401'
MSGOFFICE365_INVALID_CLIENT_ID_ERROR_CODE = 'AADSTS700016'
MSGOFFICE365_INVALID_TENANT_ID_FORMAT_ERROR_CODE = 'AADSTS900023'
MSGOFFICE365_INVALID_TENANT_ID_NOT_FOUND_ERROR_CODE = 'AADSTS90002'
MSGOFFICE365_ASSET_PARAM_CHECK_LIST_ERROR = [MSGOFFICE365_HTTP_401_STATUS_CODE, MSGOFFICE365_INVALID_CLIENT_ID_ERROR_CODE,
    MSGOFFICE365_INVALID_TENANT_ID_FORMAT_ERROR_CODE, MSGOFFICE365_INVALID_TENANT_ID_NOT_FOUND_ERROR_CODE]

# Constants relating to '_get_error_message_from_exception'

ERROR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"

# Constants relating to 'validate_integer'
MSGOFFICE365_VALID_INT_MESSAGE = "Please provide a valid integer value in the {param} parameter"
MSGOFFICE365_NON_NEG_NON_ZERO_INT_MESSAGE = (
    "Please provide a valid non-zero positive integer value in the {param} parameter"
)

MSGOFFICE365_NON_NEG_INT_MESSAGE = "Please provide a valid non-negative integer value in the {param} parameter"
MSGOFFICE365_ENCRYPTION_ERROR = "Error occurred while encrypting the state file"
MSGOFFICE365_DECRYPTION_ERROR = "Error occurred while decrypting the state file"
MSGOFFICE365_UNEXPECTED_ACCESS_TOKEN_ERROR = "Found unexpected value of access token. Please run the test connectivity to generate a new token"
MSGOFFICE365_SELECT_PARAMETER_LIST = [
    "createdDateTime",
    "lastModifiedDateTime",
    "changeKey",
    "categories",
    "receivedDateTime",
    "sentDateTime",
    "hasAttachments",
    "internetMessageId",
    "subject",
    "bodyPreview",
    "importance",
    "parentFolderId",
    "conversationId",
    "conversationIndex",
    "isDeliveryReceiptRequested",
    "isReadReceiptRequested",
    "isRead",
    "isDraft",
    "webLink",
    "inferenceClassification",
    "body",
    "sender",
    "from",
    "toRecipients",
    "ccRecipients",
    "bccRecipients",
    "replyTo",
    "flag",
    "internetMessageHeaders"
]
