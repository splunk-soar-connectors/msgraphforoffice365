# File: office365_consts.py
# Copyright (c) 2017-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


TC_STATUS_SLEEP = 2
PHANTOM_SYS_INFO_URL = "{url}rest/system_info"
PHANTOM_ASSET_INFO_URL = "{url}rest/asset/{asset_id}"
O365_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MSGOFFICE365_RUN_CONNECTIVITY_MSG = "Please Run test connectivity first to get an admin consent and generate a token that the app can use to make calls to the server. "
MSGOFFICE365_ADMIN_ACCESS_SCOPE = "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Calendars.Read"
MSGOFFICE365_ADMIN_ACCESS_SCOPE += " https://graph.microsoft.com/MailboxSettings.Read https://graph.microsoft.com/User.Read https://graph.microsoft.com/User.Read.All"
