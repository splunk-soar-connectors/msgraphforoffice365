# File: office365_consts.py
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
TC_STATUS_SLEEP = 2
MSGOFFICE365_PER_PAGE_COUNT = 999
PHANTOM_SYS_INFO_URL = "{url}rest/system_info"
PHANTOM_ASSET_INFO_URL = "{url}rest/asset/{asset_id}"
O365_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MSGOFFICE365_RUN_CONNECTIVITY_MSG = "Please run test connectivity first to complete authorization flow and "\
    "generate a token that the app can use to make calls to the server "
MSGOFFICE365_WELL_KNOWN_FOLDERS_FILTER = "displayName eq 'archive' or displayName eq 'clutter' or "\
    "displayName eq 'conflicts' or displayName eq 'conversation history' or displayName eq 'deleted items' or "\
    "displayName eq 'drafts' or displayName eq 'inbox' or displayName eq 'junk email' or displayName eq 'local failures' or"\
    " displayName eq 'msg folder root' or displayName eq 'outbox' or displayName eq 'recoverable items deletions' or "\
    "displayName eq 'scheduled' or displayName eq 'search folders' or displayName eq 'sent items' or displayName eq 'server failures' or "\
    "displayName eq 'sync issues'"
MSGOFFICE365_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file due to its unexpected format. Resetting the state file with the default format. \
Please try again."
MSGOFFICE365_AUTHORIZE_TROUBLESHOOT_MSG = 'If authorization URL fails to communicate with your Phantom instance, check whether you have:  '\
                                ' 1. Specified the Web Redirect URL of your App -- The Redirect URL should be <POST URL>/result . '\
                                ' 2. Configured the base URL of your Phantom Instance at Administration -> Company Settings -> Info'
MSGOFFICE365_INVALID_PERMISSION_ERR = "Error occurred while saving the newly generated access token "\
    "(in place of the expired token) in the state file."
MSGOFFICE365_INVALID_PERMISSION_ERR += " Please check the owner, owner group, and the permissions of the state file. The Phantom "
MSGOFFICE365_INVALID_PERMISSION_ERR += "user should have the correct access rights and ownership for the corresponding state file "\
    "(refer to readme file for more information)."
MSGOFFICE365_NO_DATA_FOUND = "No data found"
MSGOFFICE365_DUPLICATE_CONTAINER_FOUND_MSG = "duplicate container found"

MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT = 30  # in seconds

# Constants relating to '_get_error_message_from_exception'
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"

# Constants relating to 'validate_integer'
MSGOFFICE365_VALID_INT_MSG = "Please provide a valid integer value in the '{param}' action parameter"
MSGOFFICE365_NON_NEG_NON_ZERO_INT_MSG = (
    "Please provide a valid non-zero positive integer value in the '{param}' action parameter"
)
MSGOFFICE365_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the '{param}' action parameter"
