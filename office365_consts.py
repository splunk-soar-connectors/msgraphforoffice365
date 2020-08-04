# File: office365_consts.py
# Copyright (c) 2017-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


TC_STATUS_SLEEP = 2
MSGOFFICE365_PER_PAGE_COUNT = 999
PHANTOM_SYS_INFO_URL = "{url}rest/system_info"
PHANTOM_ASSET_INFO_URL = "{url}rest/asset/{asset_id}"
O365_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MSGOFFICE365_RUN_CONNECTIVITY_MSG = "Please run test connectivity first to complete authorization flow and generate a token that the app can use to make calls to the server "

MSGOFFICE365_INVALID_LIMIT = "Please provide non-zero positive integer value in the 'limit' parameter."
MSGOFFICE365_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file due to its unexpected format. Reseting the state file with the default format. \
Please try again."
MSGOFFICE365_AUTHORIZE_TROUBLESHOOT_MSG = 'If authorization URL fails to communicate with your Phantom instance, check whether you have:  '\
                                ' 1. Specified the Web Redirect URL of your App -- The Redirect URL should be <POST URL>/result . '\
                                ' 2. Configured the base URL of your Phantom Instance at Administration -> Company Settings -> Info'
MSGOFFICE365_INVALID_PERMISSION_ERR = "Error occurred while saving the newly generated access token (in place of the expired token) in the state file."
MSGOFFICE365_INVALID_PERMISSION_ERR += " Please check the owner, owner group, and the permissions of the state file. The Phantom "
MSGOFFICE365_INVALID_PERMISSION_ERR += "user should have the correct access rights and ownership for the corresponding state file (refer to readme file for more information)."
