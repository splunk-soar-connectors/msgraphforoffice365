[comment]: # "Auto-generated SOAR connector documentation"
# MS Graph for Office 365

Publisher: Splunk  
Connector Version: 3.0.1  
Product Vendor: Microsoft  
Product Name: Office 365 (MS Graph)  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.2  

This app connects to Office 365 using the MS Graph API to support investigate and generic actions related to the email messages and calendar events

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2017-2024 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Playbook Backward Compatibility

- With version 3.0.0 of the connector, the 'group_id' parameter of the 'list group members' action has been removed and two new parameters are added in the same action as follows:
  - **method** - Method(Group ID or Group e-mail) using which you want to list group members, by default it is **Group ID**.
  - **identificator** - Value of group id or group e-mail based on the **method** selected.

  Hence, it is requested to please update the existing playbooks by re-inserting
  | modifying | deleting the corresponding action blocks to ensure the correct functioning of the
  playbooks created on the earlier versions of the app.

-   The 'id' field of email artifact has been renamed to 'messageId'. Hence, it is requested to the
    end-user to please update their existing playbooks by re-inserting | modifying | deleting the
    corresponding action blocks to ensure the correct functioning of the playbooks created on the
    earlier versions of the app.

## Authentication

This app requires registration of a Microsoft Graph Application. To do so, navigate to the URL
<https://portal.azure.com> in a browser and log in with the Microsoft account, then, click **App
registrations** .  
  
On the next page, select **New registration** and give your app a name.  
  
Once the app is created, follow the below-mentioned steps:

-   Under **Certificates & secrets** select **New client secret** . Enter the **Description** and
    select the desired duration in **Expires** . Click on **Add** . Note down this **value**
    somewhere secure, as it cannot be retrieved after closing the window.

-   Under **Authentication** , select **Add a platform** . In the **Add a platform** window, select
    **Web** . The **Redirect URLs** should be filled right here. We will get **Redirect URLs** from
    the Splunk SOAR asset we create below in the section titled **Splunk SOAR Graph Asset** .

-   Under **API Permissions** Click on **Add a permission** .

-   Under the **Microsoft API** section, select **Microsoft Graph** .

-   Provide the following Application permissions to the app:

      

    -   Mail.Read (https://graph.microsoft.com/Mail.Read)

    -   Mail.ReadWrite (https://graph.microsoft.com/Mail.ReadWrite)

    -   User.Read.All (https://graph.microsoft.com/User.Read.All)

          

        -   For non-admin access, use User.Read (Delegated permission) instead
            (https://graph.microsoft.com/User.Read)

    -   Mail.Send (https://graph.microsoft.com/Mail.Send) - It is required only if you want to run
        the **send email** action.

    -   Group.Read.All (https://graph.microsoft.com/Group.Read.All) - It is required only if you
        want to run the **list events** action for the group's calendar and for the **list groups**
        and the **list group members** action.

    -   Calendar.Read (https://graph.microsoft.com/Calendars.Read) - It is required only if you want
        to run the **list events** action for the user's calendar.

    -   Calendars.ReadWrite (https://graph.microsoft.com/Calendars.ReadWrite) - It is required only
        if you want to run the **delete event** action from the user's calendar.

    -   MailboxSettings.Read (https://graph.microsoft.com/MailboxSettings.Read) - It is required
        only if you want to run the **oof status** , **list rules** and **get rule** actions.

After making these changes, click **Add permissions** , then select **Grant admin consent for
\<your_organization_name_as_on_azure_portal>** at the bottom of the screen.

## Splunk SOAR Graph Asset

When creating an asset for the **MS Graph for Office 365** app, place **Application ID** of the app
created during the app registration on the Azure Portal in the **Application ID** field and place
the client secret generated during the app registration process in the **Application Secret** field.
Then, after filling out the **Tenant** field, click **SAVE** . Both the Application/Client ID and
the Tenant ID can be found in the **Overview** tab on your app's Azure page.  
  
After saving, a new field will appear in the **Asset Settings** tab. Take the URL found in the
**POST incoming for MS Graph for Office 365 to this location** field and place it in the **Redirect
URLs** field mentioned in the previous step. To this URL, add **/result** . After doing so the URL
should look something like:  
  

https://\<splunk_soar_host>/rest/handler/msgraphforoffice365_0a0a4087-10e8-4c96-9872-b740ff26d8bb/\<asset_name>/result

  
Once again, click SAVE at the bottom of the screen.  
  
Additionally, updating the Base URL in the Company Settings is also required. Navigate to
**Administration \> Company Settings \> Info** to configure the **Base URL For Splunk SOAR** . Then,
select **Save Changes** .  
  

## User Permissions

To complete the authorization process, this app needs permission to view assets, which is not
granted by default. First, navigate to **Asset Settings \> Advanced** , to check which user is
listed under **Select a user on behalf of which automated actions can be executed** . By default,
the user will be **automation** , but this user can be changed by clicking **EDIT** at the bottom of
the window. To give this user permission to view assets, follow these steps:

-   In the main drop-down menu, select **Administration** , then select the **User Management** ,
    and under that tab, select **Roles & Permissions** . Finally, click **+ ROLE** .
-   In the **Add Role** wizard, give the role a name (e.g **Asset Viewer** ), and provide a
    description. Subsequently, under the **Users tab** , click **ADD USERS** to add the user
    assigned to the asset viewed earlier. Then click the **Permissions** tab.
-   In the permission tab, under **Basic Permissions** , give the role the **View Assets**
    privilege. Then click **SAVE** .

### Test connectivity

#### Admin User Workflow

-   Configure the asset with required details while keeping the **Admin Access Required** as
    checked.
-   While configuring the asset for the first time, keep **Admin Consent Already Provided** as
    unchecked.
-   The **Redirect URLs** must be configured before executing test connectivity. To configure
    **Redirect URLs** , checkout the section titled **Splunk SOAR Graph Asset** above.
-   After setting up the asset and user, click the **TEST CONNECTIVITY** button.
-   A window should pop up and display a URL. You will be asked to open the link in a new tab. Open
    the link in the same browser so that you are logged into Splunk SOAR for the redirect. If you
    wish to use a different browser, log in to the Splunk SOAR first, and then open the provided
    link. This new tab will redirect to the Microsoft login page.
-   Log in to the Microsoft account with the admin user.
-   You will be prompted to agree to the permissions requested by the App.
-   Review the requested permissions listed, then click **Accept** .
-   If all goes well the browser should instruct you to close the tab.
-   Now go back and check the message on the Test Connectivity dialog box, it should say **Test
    Connectivity Passed** .
-   For subsequent test connectivity or action runs, you can keep **Admin Consent Already Provided**
    config parameter as checked. This will skip the interactive flow and use the client credentials
    for generating tokens.

#### Non-Admin User Workflow

-   Configure the asset with required details while keeping the **Admin Access Required** as
    unchecked. **Admin Consent Already Provided** config parameter will be ignored in the non-admin
    workflow.
-   Provide **Access Scope** parameter in the asset configuration. All the actions will get executed
    according to the scopes provided in the **Access Scope** config parameter.
-   The **Redirect URLs** must be configured before executing test connectivity. To configure
    **Redirect URLs** , checkout the section titled **Splunk SOAR Graph Asset** above.
-   After setting up the asset and user, click the **TEST CONNECTIVITY** button.
-   A window should pop up and display a URL. You will be asked to open the link in a new tab. Open
    the link in the same browser so that you are logged into Splunk SOAR for the redirect. If you
    wish to use a different browser, log in to the Splunk SOAR first, and then open the provided
    link. This new tab will redirect to the Microsoft login page.
-   Log in to the Microsoft account.
-   You will be prompted to agree to the permissions requested by the App.
-   Review the requested permissions listed, then click **Accept** .
-   If all goes well the browser should instruct you to close the tab.
-   Now go back and check the message on the Test Connectivity dialog box, it should say **Test
    Connectivity Passed** .

  
  
The app should now be ready to be used.  

### On-Poll

**Configuration:**  

-   email_address - Ingest from the provided email address.
-   folder - To fetch the emails from the given folder name (must be provided if running ingestion)
-   get_folder_id - Retrieve the folder ID for the provided folder name/folder path automatically
    and replace the folder parameter value.
-   first_run_max_emails - Maximum containers to poll for the first scheduled polling (default -
    1000).
-   max_containers - Maximum containers to poll after the first scheduled poll completes (default -
    100).
-   extract_attachments - Extract all the attachments included in emails.
-   extract_urls - Extracts the URLs present in the emails.
-   extract_ips - Extracts the IP addresses present in the emails.
-   extract_domains - Extract the domain names present in the emails.
-   extract_hashes - Extract the hashes present in the emails (MD5).
-   ingest_eml - Fetch the EML file content for the 'item attachment' and ingest it into the vault.
    This will only ingest the first level 'item attachment' as an EML file. The nested item
    attachments will not be ingested into the vault. If the extract_attachments flag is set to
    false, then the application will also skip the EML file ingestion regardless of this flag value.
-   extract_eml - When polling is on and extract_eml is enabled, it will add the eml files of the
    root email in the vault.

If extract_attachments is set to true, only fileAttachment will be ingested. If both ingest_eml and
extract_attachments are set to true, then both fileAttachment and itemAttachment will be ingested.

## Guidelines to provide folder parameter value

This is applicable to 'on poll', 'copy email', 'move email', and 'run query' actions.

-   The **get_folder_id** parameter should be enabled only when you have specified folder
    name/folder path in the **folder** parameter.
-   If you provide folder ID in the **folder** parameter and set **get_folder_id** parameter to
    true, it will throw an error of folder ID not found for given folder name (because the action
    considers folder parameter value as folder name/folder path).
-   The **folder** parameter must be either a (case sensitive) well-known name (
    <https://docs.microsoft.com/en-us/graph/api/resources/mailfolder?view=graph-rest-1.0> ) or the
    internal o365 folder ID.
-   The folder parameter supports nested folder paths. To specify the complete folder path using the
    **'/'** (forward slash) as the separator.  
    e.g. to specify a folder named *phishing* which is nested within (is a child of) *Inbox* , set
    the value as **Inbox/phishing** . If a folder name has a literal forward slash('/') in the name
    escape it with a backslash('\\\\') to differentiate.

## State file permissions

Please check the permissions for the state file as mentioned below.

#### State file path

-   For unprivileged instance:
    /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/\<appid>/\<asset_id>\_state.json

#### State file permissions

-   File rights: rw-rw-r-- (664) (The Splunk SOAR user should have read and write access for the
    state file)
-   File owner: Appropriate Splunk SOAR user

### Note

-   An optional parameter **Admin Access Required** has been added to this app. In most cases, this
    should remain checked, as admin access is required for email use cases. If the desired
    integration is to integrate with only one user's calendar, you may consider unchecking this box.
    If unchecked, it allows a non-admin user to provide access to a specific account. This
    functionality will ONLY work with the **list events** functionality. If unchecked, the **Access
    scope** *must* be used. The default scope will work for listing calendar events. Additional
    information on scope can be found
    [here.](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes)
-   As per the Microsoft known issues for **Group.Read.All** permission (
    [here](https://docs.microsoft.com/en-us/graph/known-issues#groups) ), if you want to run the
    **list events** for fetching group's calendar events, you have to uncheck an optional parameter
    **Admin Access Required** and provide **Group.Read.All
    (https://graph.microsoft.com/Group.Read.All)** permission into the scope parameter in the asset
    configuration parameters. If an asset parameter **Admin Access Required** checked and configured
    the app with above mentioned all the application permissions (which includes **Group.Read.All**
    application permission), it throws an error like **Access is denied** while running **list
    events** action for fetching group's calendar events. Because of the known issue of
    **Group.Read.All** application permission, this permission required admin consent (on behalf of
    the user permission) to fetch the group's calendar events.
-   If the parameter **Admin Access Required** is unchecked, you have to provide a **scope**
    parameter in the asset configuration. All the actions will get executed according to the scopes
    provided in the **scope** config parameter. The actions will throw an appropriate error if the
    scope of the corresponding permission is not provided by the end-user.
-   There is an API limitation that will affect run_query action when providing Unicode values in
    the subject or in the body as parameters and if the result count exceeds 999, the action will
    fail.
-   The sensitive values are stored encrypted in the state file.

  

## Increase the maximum limit for ingestion

The steps are as follows:

1.  Open the **/opt/phantom/usr/nginx/conf/conf.d/phantom-nginx-server.conf** file on the SOAR
    instance.
2.  Change that value of the **client_max_body_size** variable as per your needs.
3.  Save the configuration file.
4.  Reload nginx service using **service nginx reload** or try restarting the nginx server from SOAR
    platform: Go to **Administrator->System Health-> System Health** then restart the nginx server.

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Office365 server. Below are the default
ports used by the Splunk SOAR Connector.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Office 365 (MS Graph) asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant** |  required  | string | Tenant ID (e.g. 1e309abf-db6c-XXXX-a1d2-XXXXXXXXXXXX)
**client_id** |  required  | string | Application ID
**client_secret** |  required  | password | Application Secret
**admin_access** |  optional  | boolean | Admin Access Required
**admin_consent** |  optional  | boolean | Admin Consent Already Provided
**scope** |  optional  | string | Access Scope (for use with non-admin access; space-separated)
**ph_2** |  optional  | ph | 
**email_address** |  optional  | string | Email Address of the User (On Poll)
**folder** |  optional  | string | Mailbox folder name/folder path or the internal office365 folder ID to ingest (On Poll)
**get_folder_id** |  optional  | boolean | Retrieve the folder ID for the provided folder name/folder path automatically and replace the folder parameter value (On Poll)
**ph_3** |  optional  | ph | 
**first_run_max_emails** |  optional  | numeric | Maximum Containers for scheduled polling first time
**max_containers** |  optional  | numeric | Maximum Containers for scheduled polling
**extract_attachments** |  optional  | boolean | Extract Attachments
**extract_urls** |  optional  | boolean | Extract URLs
**extract_ips** |  optional  | boolean | Extract IPs
**extract_domains** |  optional  | boolean | Extract Domain Names
**extract_hashes** |  optional  | boolean | Extract Hashes
**ingest_eml** |  optional  | boolean | Ingest EML file for the itemAttachment
**ingest_manner** |  optional  | string | How to Ingest (during ingestion, should the app get the latest emails or the oldest)
**retry_count** |  optional  | numeric | Maximum attempts to retry the API call (Default: 3)
**retry_wait_time** |  optional  | numeric | Delay in seconds between retries (Default: 60)
**extract_eml** |  optional  | boolean | Extract root (primary) email as Vault

### Supported Actions  
[test connectivity](#action-test-connectivity) - Use supplied credentials to generate a token with MS Graph  
[generate token](#action-generate-token) - Generate a token  
[oof check](#action-oof-check) - Get user's out of office status  
[list events](#action-list-events) - List events from user or group calendar  
[get rule](#action-get-rule) - Get the properties and relationships of a messageRule object  
[list rules](#action-list-rules) - Get all the messageRule objects defined for the user's inbox  
[list users](#action-list-users) - Retrieve a list of users  
[list groups](#action-list-groups) - List all the groups in an organization, including but not limited to Office 365 groups  
[list group members](#action-list-group-members) - List all the members in group by group ID or group e-mail address  
[list folders](#action-list-folders) - Retrieve a list of mail folders  
[copy email](#action-copy-email) - Copy an email to a folder  
[move email](#action-move-email) - Move an email to a folder  
[delete email](#action-delete-email) - Delete an email  
[delete event](#action-delete-event) - Delete an event from user calendar  
[get email](#action-get-email) - Get an email from the server  
[get email properties](#action-get-email-properties) - Get non-standard email properties from the server  
[run query](#action-run-query) - Search emails  
[create folder](#action-create-folder) - Create a new folder  
[get folder id](#action-get-folder-id) - Get the API ID of the folder  
[send email](#action-send-email) - Sends an email with optional text rendering. Attachments are allowed a Content-ID tag for reference within the html  
[on poll](#action-on-poll) - Ingest emails from Office 365 using Graph API  
[update email](#action-update-email) - Update an email on the server  
[block sender](#action-block-sender) - Add the sender email into the block list  
[unblock sender](#action-unblock-sender) - Remove the sender email from the block list  
[resolve name](#action-resolve-name) - Verify aliases and resolve display names to the appropriate user  

## action: 'test connectivity'
Use supplied credentials to generate a token with MS Graph

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'generate token'
Generate a token

Type: **generic**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Token generated 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'oof check'
Get user's out of office status

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID/Principal name | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.user_id | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email`  |   eeb3645f-df19-58a1-0e9c-ghi234cb5f6f 
action_result.data.\*.@odata.context | string |  `url`  |   https://test.abc.com/v1.0/$metadata#users('EXAMPLEUSERID')/mailboxSettings/automaticRepliesSetting 
action_result.data.\*.@odata.etag | string |  |  
action_result.data.\*.externalAudience | string |  |   all 
action_result.data.\*.externalReplyMessage | string |  |  
action_result.data.\*.internalReplyMessage | string |  |  
action_result.data.\*.scheduledEndDateTime.dateTime | string |  |   2022-03-15T12:00:00.0000000 
action_result.data.\*.scheduledEndDateTime.timeZone | string |  |   UTC 
action_result.data.\*.scheduledStartDateTime.dateTime | string |  |   2022-03-14T12:00:00.0000000 
action_result.data.\*.scheduledStartDateTime.timeZone | string |  |   UTC 
action_result.data.\*.status | string |  |   alwaysEnabled 
action_result.summary.events_matched | numeric |  |   1 
action_result.message | string |  |   Successfully retrieved out of office status 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list events'
List events from user or group calendar

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  optional  | User ID/Principal name | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email` 
**group_id** |  optional  | Group ID | string |  `msgoffice365 group id` 
**filter** |  optional  | OData query to filter/search for specific results | string | 
**limit** |  optional  | Maximum number of events to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.filter | string |  |   $filter=subject eq 'Test2' 
action_result.parameter.group_id | string |  `msgoffice365 group id`  |   3d9c58f8-9f38-4016-93ac-b61095f31c48 
action_result.parameter.limit | numeric |  |   20 
action_result.parameter.user_id | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email`  |   test@testdomain.abc.com 
action_result.data.\*.@odata.etag | string |  |   W/"b1MzKFCcdkuJ24Mc2VsdjwABAdhQhg==" 
action_result.data.\*.allowNewTimeProposals | boolean |  |   True  False 
action_result.data.\*.attendee_list | string |  |   H-test, o365group 
action_result.data.\*.attendees.\*.emailAddress.address | string |  `email`  |   H-test@testdomain.abc.com 
action_result.data.\*.attendees.\*.emailAddress.name | string |  |   H-test 
action_result.data.\*.attendees.\*.status.response | string |  |   none 
action_result.data.\*.attendees.\*.status.time | string |  |   0001-01-01T00:00:00Z 
action_result.data.\*.attendees.\*.type | string |  |   required 
action_result.data.\*.body.content | string |  |   `<html><head><meta name="Generator" content="Test Server">\\r\\n<!-- converted from text -->\\r\\n<style><!-- .EmailQuote { margin-left: 1pt; padding-left: 4pt; border-left: #800000 2px solid; } --></style></head>\\r\\n<body>\\r\\n<font size="2"><span style="font-size:11pt;"><div class="PlainText">&nbsp;</div></span></font>\\r\\n</body>\\r\\n</html>\\r\\n` 
action_result.data.\*.body.contentType | string |  |   html 
action_result.data.\*.bodyPreview | string |  |  
action_result.data.\*.calendar@odata.associationLink | string |  `url`  |   https://test.abc.com/v1.0/users('EXAMPLEUSERID')/calendars('EXAMPLECALENDERID')/$ref 
action_result.data.\*.calendar@odata.navigationLink | string |  `url`  |   https://test.abc.com/v1.0/users('EXAMPLEUSERID')/calendars('EXAMPLECALENDERID') 
action_result.data.\*.categories.\*.name | string |  |  
action_result.data.\*.changeKey | string |  |   b1MzKFCcdkuJ24Mc2VsdjwABAdhQhg== 
action_result.data.\*.createdDateTime | string |  |   2019-10-03T09:03:42.4958512Z 
action_result.data.\*.end.dateTime | string |  |   2019-10-04T15:30:00.0000000 
action_result.data.\*.end.timeZone | string |  |   UTC 
action_result.data.\*.hasAttachments | boolean |  |   True  False 
action_result.data.\*.hideAttendees | boolean |  |   True  False 
action_result.data.\*.iCalUId | string |  |   040000008200E00074C5B7101A82E00800000000347B5D74C979D5010000000000000000100000003F2152B556F23543B1B9C751CCD711A3 
action_result.data.\*.id | string |  `msgoffice365 event id`  |   AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwBGAAAAAADRlY7ewL4xToKRDciQog5UBwBvUzMoUJx2S4nbgxzZWx2PAAAAAAENAABvUzMoUJx2S4nbgxzZWx2PAAEB90vfAAA= 
action_result.data.\*.importance | string |  |   normal 
action_result.data.\*.isAllDay | boolean |  |   True  False 
action_result.data.\*.isCancelled | boolean |  |   True  False 
action_result.data.\*.isDraft | boolean |  |   True  False 
action_result.data.\*.isOnlineMeeting | boolean |  |   True  False 
action_result.data.\*.isOrganizer | boolean |  |   True  False 
action_result.data.\*.isReminderOn | boolean |  |   True  False 
action_result.data.\*.lastModifiedDateTime | string |  |   2019-10-04T15:24:43.0639836Z 
action_result.data.\*.location.address.city | string |  |   City 
action_result.data.\*.location.address.countryOrRegion | string |  |   Country 
action_result.data.\*.location.address.postalCode | string |  |   245004 
action_result.data.\*.location.address.state | string |  |   State 
action_result.data.\*.location.address.street | string |  |   Location Address 
action_result.data.\*.location.coordinates.latitude | numeric |  |   23.0011 
action_result.data.\*.location.coordinates.longitude | numeric |  |   72.4994 
action_result.data.\*.location.displayName | string |  |   Test 
action_result.data.\*.location.locationType | string |  |   default 
action_result.data.\*.location.locationUri | string |  `url`  |   https://www.bingapis.com/api/v6/localbusinesses/YN4070x2912827763012539383?setLang=en 
action_result.data.\*.location.uniqueId | string |  |   f30c3e81-78b7-4f47-8890-f60c3f57e199 
action_result.data.\*.location.uniqueIdType | string |  |   unknown 
action_result.data.\*.locations.\*.address.city | string |  |   City 
action_result.data.\*.locations.\*.address.countryOrRegion | string |  |   Country 
action_result.data.\*.locations.\*.address.postalCode | string |  |   245004 
action_result.data.\*.locations.\*.address.state | string |  |   State 
action_result.data.\*.locations.\*.address.street | string |  |   Location Address 
action_result.data.\*.locations.\*.coordinates.latitude | numeric |  |   23.0011 
action_result.data.\*.locations.\*.coordinates.longitude | numeric |  |   72.4994 
action_result.data.\*.locations.\*.displayName | string |  |   Test Building Address Bus Stop 
action_result.data.\*.locations.\*.locationType | string |  |   localBusiness 
action_result.data.\*.locations.\*.locationUri | string |  `url`  |   https://www.bingapis.com/api/v6/localbusinesses/YN4070x2912827763012539383?setLang=en 
action_result.data.\*.locations.\*.uniqueId | string |  |   f30c3e81-78b7-4f47-8890-f60c3f57e199 
action_result.data.\*.locations.\*.uniqueIdType | string |  |   locationStore 
action_result.data.\*.occurrenceId | string |  |  
action_result.data.\*.onlineMeeting | string |  |  
action_result.data.\*.onlineMeetingProvider | string |  |   unknown 
action_result.data.\*.onlineMeetingUrl | string |  `url`  |  
action_result.data.\*.organizer.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.organizer.emailAddress.name | string |  |   Test Name 
action_result.data.\*.originalEndTimeZone | string |  |   Pacific Standard Time 
action_result.data.\*.originalStartTimeZone | string |  |   Pacific Standard Time 
action_result.data.\*.recurrence | string |  |  
action_result.data.\*.reminderMinutesBeforeStart | numeric |  |   15 
action_result.data.\*.responseRequested | boolean |  |   False  True 
action_result.data.\*.responseStatus.response | string |  |   organizer 
action_result.data.\*.responseStatus.time | string |  |   0001-01-01T00:00:00Z 
action_result.data.\*.sensitivity | string |  |   normal 
action_result.data.\*.seriesMasterId | string |  |  
action_result.data.\*.showAs | string |  |   busy 
action_result.data.\*.start.dateTime | string |  |   2019-10-04T15:00:00.0000000 
action_result.data.\*.start.timeZone | string |  |   UTC 
action_result.data.\*.subject | string |  |   New event - 1 
action_result.data.\*.transactionId | string |  |   b2e47e5d-8f87-9845-c507-7be56490c432 
action_result.data.\*.type | string |  |   singleInstance 
action_result.data.\*.webLink | string |  `url`  |   https://outlook.office365.com/owa/?itemid=AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwBGAAAAAADRlY7ewL4xToKRDciQog5UBwBvUzMoUJx2S4nbgxzZWx2PAAAAAAENAABvUzMoUJx2S4nbgxzZWx2PAAEB90vfAAA%3D&exvsurl=1&path=/calendar/item 
action_result.data.locations.\*.displayName | string |  |  
action_result.summary.events_matched | numeric |  |   8 
action_result.message | string |  |   Successfully retrieved 8 events 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get rule'
Get the properties and relationships of a messageRule object

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID/Principal name | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email` 
**rule_id** |  required  | Inbox rule ID | string |  `msgoffice365 rule id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.rule_id | string |  `msgoffice365 rule id`  |   AQAABgFGMAc= 
action_result.parameter.user_id | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email`  |   test@testdomain.abc.com 
action_result.data.\*.@odata.context | string |  |   https://graph.microsoft.com/v1.0/$metadata#users('eeb3645f-df19-47a1-8e8c-fcd234cb5f6f')/mailFolders('inbox')/messageRules/$entity 
action_result.data.\*.actions_copyToFolder | string |  |   AQMkAGYxNGJmOWQyLTlhMjctNGRiOS1iODU0LTA1ZWE3ZmQ3NDU3MQAuAAADeDDJKaEf4EihMWU6SZgKbAEA07XhOkNngkCkqoNfY_k-jQAF6qrTswAAAA== 
action_result.data.\*.actions_stopProcessingRules | boolean |  |   True  False 
action_result.data.\*.conditions_fromAddresses_0_emailAddress_address | string |  `email`  |   test@test.com 
action_result.data.\*.conditions_fromAddresses_0_emailAddress_name | string |  |   Ryan Edwards 
action_result.data.\*.displayName | string |  |   Move all messages from Casey Edwards to test-msgoffice365-test 
action_result.data.\*.hasError | boolean |  |   True  False 
action_result.data.\*.id | string |  |   AQAABgFGL8A= 
action_result.data.\*.isEnabled | boolean |  |   True  False 
action_result.data.\*.isReadOnly | boolean |  |   True  False 
action_result.data.\*.sequence | numeric |  |   2 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully retrieved specified inbox rule 
action_result.message | string |  |   Successfully retrieved specified inbox rule 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list rules'
Get all the messageRule objects defined for the user's inbox

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID/Principal name | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.user_id | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email`  |   test@testdomain.abc.com 
action_result.data.\*.actions.copyToFolder | string |  `msgoffice365 folder id`  |   AQMkAGYxNGJmOWQyLTlhMjctNGRiOS1iODU0LTA1ZWE3ZmQ3NDU3MQAuAAADeDDJKaEf4EihMWU6SZgKbAEA07XhOkNngkCkqoNfY_k-jQAF6qrTswAAAA== 
action_result.data.\*.actions.delete | boolean |  |   True  False 
action_result.data.\*.actions.markAsRead | boolean |  |   True  False 
action_result.data.\*.actions.moveToFolder | string |  `msgoffice365 folder id`  |   AQMkAGYxNGJmOWQyLTlhMjctNGRiOS1iODU0LTA1ZWE3ZmQ3NDU3MQAuAAADeDDJKaEf4EihMWU6SZgKbAEA07XhOkNngkCkqoNfY_k-jQAF6qrTtAAAAA== 
action_result.data.\*.actions.stopProcessingRules | boolean |  |   True  False 
action_result.data.\*.conditions.fromAddresses.\*.emailAddress.address | string |  `email`  |   test@abc.com 
action_result.data.\*.conditions.fromAddresses.\*.emailAddress.name | string |  |   Ryan Edwards 
action_result.data.\*.displayName | string |  |   Emails to Trash 
action_result.data.\*.hasError | boolean |  |   True  False 
action_result.data.\*.id | string |  `msgoffice365 rule id`  |   AQAABiQdmB8= 
action_result.data.\*.isEnabled | boolean |  |   True  False 
action_result.data.\*.isReadOnly | boolean |  |   True  False 
action_result.data.\*.sequence | numeric |  |   1 
action_result.summary.total_rules_returned | numeric |  |   14 
action_result.message | string |  |   Successfully retrieved 7 rules 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list users'
Retrieve a list of users

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | Search for specific results | string | 
**limit** |  optional  | Maximum number of users to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.filter | string |  |   displayName eq 'User Name' 
action_result.parameter.limit | numeric |  |   20 
action_result.data.\*.businessPhones | string |  |   2056120271 
action_result.data.\*.displayName | string |  |   Test Admin 
action_result.data.\*.givenName | string |  |   Test 
action_result.data.\*.id | string |  `msgoffice365 user id`  |   6132ca31-7a09-434f-a269-abe836d0c01e 
action_result.data.\*.jobTitle | string |  |  
action_result.data.\*.mail | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.mobilePhone | string |  |  
action_result.data.\*.officeLocation | string |  |  
action_result.data.\*.preferredLanguage | string |  |  
action_result.data.\*.surname | string |  |   Globaltest 
action_result.data.\*.userPrincipalName | string |  `msgoffice365 user principal name`  `email`  |   test@testdomain.abc.com 
action_result.summary.total_users_returned | numeric |  |   11 
action_result.message | string |  |   Successfully retrieved 11 users 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list groups'
List all the groups in an organization, including but not limited to Office 365 groups

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | Search for specific results | string | 
**limit** |  optional  | Maximum number of groups to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.filter | string |  |   displayName eq 'Group Name' 
action_result.parameter.limit | numeric |  |   20 
action_result.data.\*.classification | string |  |  
action_result.data.\*.createdDateTime | string |  |   2018-09-11T09:51:07Z 
action_result.data.\*.creationOptions | string |  |   ExchangeProvisioningFlags:3552 
action_result.data.\*.deletedDateTime | string |  |  
action_result.data.\*.description | string |  |   This is for testing purpose 
action_result.data.\*.displayName | string |  |   Test-test-site 
action_result.data.\*.expirationDateTime | string |  |  
action_result.data.\*.groupTypes | string |  |   Unified 
action_result.data.\*.id | string |  `msgoffice365 group id`  |   2a201c95-101b-42d9-a7af-9a2fdf8193f1 
action_result.data.\*.isAssignableToRole | string |  |  
action_result.data.\*.mail | string |  `email`  `msgoffice365 group e-mail address`  |   Test-test-site@testdomain.abc.com 
action_result.data.\*.mailEnabled | boolean |  |   True  False 
action_result.data.\*.mailNickname | string |  |   Test-test-site 
action_result.data.\*.membershipRule | string |  |  
action_result.data.\*.membershipRuleProcessingState | string |  |  
action_result.data.\*.onPremisesDomainName | string |  |  
action_result.data.\*.onPremisesLastSyncDateTime | string |  |  
action_result.data.\*.onPremisesNetBiosName | string |  |  
action_result.data.\*.onPremisesSamAccountName | string |  |  
action_result.data.\*.onPremisesSecurityIdentifier | string |  |  
action_result.data.\*.onPremisesSyncEnabled | string |  |  
action_result.data.\*.preferredDataLocation | string |  |  
action_result.data.\*.preferredLanguage | string |  |  
action_result.data.\*.proxyAddresses | string |  |   SMTP:test-h@testdomain.abc.com 
action_result.data.\*.renewedDateTime | string |  |   2018-09-11T09:51:07Z 
action_result.data.\*.resourceBehaviorOptions | string |  |   WelcomeEmailDisabled 
action_result.data.\*.resourceProvisioningOptions | string |  |   Team 
action_result.data.\*.securityEnabled | boolean |  |   True  False 
action_result.data.\*.securityIdentifier | string |  |   S-1-12-1-294681889-1319597617-672379543-28952022 
action_result.data.\*.theme | string |  |  
action_result.data.\*.visibility | string |  |   Private 
action_result.summary.total_groups_returned | numeric |  |   9 
action_result.message | string |  |   Successfully retrieved 9 groups 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list group members'
List all the members in group by group ID or group e-mail address

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**method** |  required  | Method to use to list group members | string | 
**identificator** |  required  | Group ID or group e-mail address, based on the selected method | string |  `msgoffice365 group id`  `msgoffice365 group e-mail address` 
**get_transitive_members** |  optional  | Get a list of the group's members. A group can have users, devices, organizational contacts, and other groups as members. This operation is transitive and returns a flat list of all nested members | boolean | 
**filter** |  optional  | Search for specific results | string | 
**limit** |  optional  | Maximum number of members to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.filter | string |  |   displayName eq 'Group Name' 
action_result.parameter.get_transitive_members | boolean |  |   True  False 
action_result.parameter.method | string |  |   Group ID  Group e-mail 
action_result.parameter.identificator | string |  `msgoffice365 group id`  `msgoffice365 group e-mail address`  |   TEST7d21-7631-4ea7-97b2-1328d1c5b901  example@test.com 
action_result.parameter.limit | numeric |  |   20 
action_result.data.\*.@odata.type | string |  |   #test.abc.user 
action_result.data.\*.businessPhones | string |  |   2056120271 
action_result.data.\*.displayName | string |  |   Test Admin 
action_result.data.\*.givenName | string |  |   Test 
action_result.data.\*.id | string |  `msgoffice365 user id`  |   6132ca31-7a09-434f-a269-abe836d0c01e 
action_result.data.\*.jobTitle | string |  |  
action_result.data.\*.mail | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.mobilePhone | string |  |  
action_result.data.\*.officeLocation | string |  |  
action_result.data.\*.preferredLanguage | string |  |  
action_result.data.\*.surname | string |  |   Globaltest 
action_result.data.\*.userPrincipalName | string |  `msgoffice365 user principal name`  `email`  |   test@testdomain.abc.com 
action_result.summary.total_members_returned | numeric |  |   9 
action_result.message | string |  |   Successfully retrieved 9 groups 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list folders'
Retrieve a list of mail folders

Type: **investigate**  
Read only: **True**

If you want to list all the child folders (includes all the sub-levels) of the specific parent folder, then, you have to provide the parent <b>folder_id</b> parameter. If you don't provide <b>folder_id</b> it will list all the folders on Office 365 account (includes all the sub-level folders).

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID/Principal name | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email` 
**folder_id** |  optional  | Parent mail folder ID | string |  `msgoffice365 folder id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.folder_id | string |  `msgoffice365 folder id`  |   AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwAuAAAAAADRlY7ewL4xToKRDciQog5UAQBvUzMoUJx2S4nbgxzZWx2PAAD9nLiRAAA= 
action_result.parameter.user_id | string |  `msgoffice365 user id`  `msgoffice365 user principal name`  `email`  |   test@testdomain.abc.com 
action_result.data.\*.childFolderCount | numeric |  |   1 
action_result.data.\*.displayName | string |  |   test 
action_result.data.\*.id | string |  `msgoffice365 folder id`  |   AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwAuAAAAAADRlY7ewL4xToKRDciQog5UAQBvUzMoUJx2S4nbgxzZWx2PAAD9nLiRAAA= 
action_result.data.\*.isHidden | boolean |  |   True  False 
action_result.data.\*.parentFolderId | string |  `msgoffice365 folder id`  |   AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwAuAAAAAADRlY7ewL4xToKRDciQog5UAQBvUzMoUJx2S4nbgxzZWx2PAAAAAAEIAAA= 
action_result.data.\*.sizeInBytes | numeric |  |   7920 
action_result.data.\*.totalItemCount | numeric |  |   0 
action_result.data.\*.unreadItemCount | numeric |  |   0 
action_result.summary.total_folders_returned | numeric |  |   14 
action_result.message | string |  |   Successfully retrieved 14 mail folders 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'copy email'
Copy an email to a folder

Type: **generic**  
Read only: **False**

The <b>get_folder_id</b> parameter should be enabled only when you have specified folder name/folder path in the <b>folder</b> parameter. If you provide folder ID in the <b>folder</b> parameter and set <b>get_folder_id</b> parameter to true, it will throw an error of folder ID not found for given folder name (because the action considers folder parameter value as folder name/folder path). The <b>folder</b> parameter must be either a (case sensitive) well-known name [list here; https://docs.microsoft.com/en-us/graph/api/resources/mailfolder?view=graph-rest-1.0] or the internal o365 folder ID. The action supports copying to a folder that is nested within another. To copy in such a folder, specify the complete folder path using the <b>'/'</b> (forward slash) as the separator.<br>e.g. to search in a folder named <i>phishing</i> which is nested within (is a child of) <i>Inbox</i>, set the value as <b>Inbox/phishing</b>. If a folder name has a literal forward slash('/') in the name escape it with a backslash('\\') to differentiate.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to copy | string |  `msgoffice365 message id` 
**email_address** |  required  | Source mailbox (email) | string |  `email` 
**folder** |  required  | Destination folder; this must be either a (case-sensitive) well-known name or the internal o365 folder ID | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  `msgoffice365 folder id` 
**get_folder_id** |  optional  | Assume the folder parameter contains a folder name/folder path, separated by '/' ; i.e. Inbox/dir1/dir2/dir3. If this parameter is enabled, it retrieves the folder ID for the provided folder name/folder path automatically and replaces the parameter value | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.email_address | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.folder | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  `msgoffice365 folder id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAuAAADyW3X5P7Hb0_MMHKonvdoWQEAQSl1b8BFiEmbqZql_JiUtwAAAgEbAAAA 
action_result.parameter.get_folder_id | boolean |  |   True  False 
action_result.parameter.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwABS2DpdwAAAA== 
action_result.data.\*.@odata.context | string |  `url`  |   https://test.abc.com/v1.0/$metadata#message 
action_result.data.\*.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFQwHj9" 
action_result.data.\*.@odata.type | string |  |   #test.abc.message 
action_result.data.\*.bccRecipients.email | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.bccRecipients.name | string |  |   Test Name 
action_result.data.\*.body.content | string |  |   `plain text?\\r\\n` 
action_result.data.\*.body.contentType | string |  |   text 
action_result.data.\*.bodyPreview | string |  |   plain text? 
action_result.data.\*.categories | string |  |  
action_result.data.\*.ccRecipients.email | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.ccRecipients.name | string |  |   Test Name 
action_result.data.\*.changeKey | string |  |   CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFQwHj9 
action_result.data.\*.conversationId | string |  |   AAQkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAQANDpL7xEHORGgd1idbVXqcg= 
action_result.data.\*.conversationIndex | string |  |   AQHW+IHb9hH4JnJtjUmniPjyy9YF2Y== 
action_result.data.\*.createdDateTime | string |  |   2017-10-25T22:29:01Z 
action_result.data.\*.flag.flagStatus | string |  |   notFlagged 
action_result.data.\*.from.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.from.emailAddress.name | string |  |   Test Name 
action_result.data.\*.hasAttachments | boolean |  |   True  False 
action_result.data.\*.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEbAAAAQSl1b8BFiEmbqZql_JiUtwABUH-stgAAAA== 
action_result.data.\*.importance | string |  |   normal 
action_result.data.\*.inferenceClassification | string |  |   focused 
action_result.data.\*.internetMessageId | string |  `msgoffice365 internet message id`  |   <CABO4XoNKorysqU1nR=of7qDBFbR1cv9icBSb38M=g3ryBb=CrA@mail.test.com> 
action_result.data.\*.isDeliveryReceiptRequested | boolean |  |   True  False 
action_result.data.\*.isDraft | boolean |  |   True  False 
action_result.data.\*.isRead | boolean |  |   True  False 
action_result.data.\*.isReadReceiptRequested | boolean |  |   True  False 
action_result.data.\*.lastModifiedDateTime | string |  |   2017-11-02T23:58:59Z 
action_result.data.\*.parentFolderId | string |  `msgoffice365 folder id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAuAAADyW3X5P7Hb0_MMHKonvdoWQEAQSl1b8BFiEmbqZql_JiUtwAAAgEbAAAA 
action_result.data.\*.receivedDateTime | string |  |   2017-10-25T22:29:01Z 
action_result.data.\*.replyTo | string |  |  
action_result.data.\*.sender.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.sender.emailAddress.name | string |  |   Test Name 
action_result.data.\*.sentDateTime | string |  |   2017-10-25T22:28:57Z 
action_result.data.\*.subject | string |  `msgoffice365 subject`  |   more body formats? 
action_result.data.\*.toRecipients.\*.emailAddress.address | string |  `email`  |   Test@testdomain.abc.com 
action_result.data.\*.toRecipients.\*.emailAddress.name | string |  |   Test Name 
action_result.data.\*.webLink | string |  `url`  |   https://outlook.office365.com/owa/?ItemID=AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0%2BMMHKonvdoWQcAQSl1b8BFiEmbqZql%2BJiUtwAAAgEbAAAAQSl1b8BFiEmbqZql%2BJiUtwABUH%2FstgAAAA%3D%3D&exvsurl=1&viewmodel=ReadMessageItem 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully copied email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'move email'
Move an email to a folder

Type: **generic**  
Read only: **False**

The <b>get_folder_id</b> parameter should be enabled only when you have specified folder name/folder path in the <b>folder</b> parameter. If you provide folder ID in the <b>folder</b> parameter and set <b>get_folder_id</b> parameter to true, it will throw an error of folder ID not found for given folder name (because the action considers folder parameter value as folder name/folder path). The <b>folder</b> parameter must be either a (case sensitive) well-known name [list here; https://docs.microsoft.com/en-us/graph/api/resources/mailfolder?view=graph-rest-1.0] or the internal o365 folder ID. The action supports moving to a folder that is nested within another. To copy in such a folder, specify the complete folder path using the <b>'/'</b> (forward slash) as the separator.<br>e.g. to search in a folder named <i>phishing</i> which is nested within (is a child of) <i>Inbox</i>, set the value as <b>Inbox/phishing</b>. If a folder name has a literal forward slash('/') in the name escape it with a backslash('\\') to differentiate.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to move | string |  `msgoffice365 message id` 
**email_address** |  required  | Source mailbox (email) | string |  `email` 
**folder** |  required  | Destination folder; this must be either a (case-sensitive) well-known name or the internal o365 folder ID | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  `msgoffice365 folder id` 
**get_folder_id** |  optional  | Assume the folder parameter contains a folder name/folder path, separated by '/'(forward slash) ; i.e. Inbox/dir1/dir2/dir3. If this parameter is enabled, it retrieves the folder ID for the provided folder name/folder path automatically and replaces the parameter value | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.email_address | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.folder | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  `msgoffice365 folder id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAuAAADyW3X5P7Hb0_MMHKonvdoWQEAQSl1b8BFiEmbqZql_JiUtwAAAgEbAAAA 
action_result.parameter.get_folder_id | boolean |  |   True  False 
action_result.parameter.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwABS2DpdwAAAA== 
action_result.data.\*.@odata.context | string |  `url`  |   https://test.abc.com/v1.0/$metadata#message 
action_result.data.\*.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFQwHj9" 
action_result.data.\*.@odata.type | string |  |   #test.abc.message 
action_result.data.\*.bccRecipients.email | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.bccRecipients.name | string |  |   Test User 
action_result.data.\*.body.content | string |  |   `plain text?\\r\\n` 
action_result.data.\*.body.contentType | string |  |   text 
action_result.data.\*.bodyPreview | string |  |   plain text? 
action_result.data.\*.categories | string |  |  
action_result.data.\*.ccRecipients.email | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.ccRecipients.name | string |  |   Test Name 
action_result.data.\*.changeKey | string |  |   CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFQwHj9 
action_result.data.\*.conversationId | string |  |   AAQkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAQANDpL7xEHORGgd1idbVXqcg= 
action_result.data.\*.conversationIndex | string |  |   AQHW+IHb9hH4JnJtjUmniPjyy9YF1Y== 
action_result.data.\*.createdDateTime | string |  |   2017-10-25T22:29:01Z 
action_result.data.\*.flag.flagStatus | string |  |   notFlagged 
action_result.data.\*.from.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.from.emailAddress.name | string |  |   Test Name 
action_result.data.\*.hasAttachments | boolean |  |   True  False 
action_result.data.\*.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEbAAAAQSl1b8BFiEmbqZql_JiUtwABUH-stgAAAA== 
action_result.data.\*.importance | string |  |   normal 
action_result.data.\*.inferenceClassification | string |  |   focused 
action_result.data.\*.internetMessageId | string |  `msgoffice365 internet message id`  |   <CABO4XoNKorysqU1nR=of7qDBFbR1cv9icBSb38M=g3ryBb=CrA@mail.test.com> 
action_result.data.\*.isDeliveryReceiptRequested | boolean |  |   True  False 
action_result.data.\*.isDraft | boolean |  |   True  False 
action_result.data.\*.isRead | boolean |  |   True  False 
action_result.data.\*.isReadReceiptRequested | boolean |  |   True  False 
action_result.data.\*.lastModifiedDateTime | string |  |   2017-11-02T23:58:59Z 
action_result.data.\*.parentFolderId | string |  `msgoffice365 folder id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAuAAADyW3X5P7Hb0_MMHKonvdoWQEAQSl1b8BFiEmbqZql_JiUtwAAAgEbAAAA 
action_result.data.\*.receivedDateTime | string |  |   2017-10-25T22:29:01Z 
action_result.data.\*.replyTo | string |  |  
action_result.data.\*.sender.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.sender.emailAddress.name | string |  |   Test Name 
action_result.data.\*.sentDateTime | string |  |   2017-10-25T22:28:57Z 
action_result.data.\*.subject | string |  `msgoffice365 subject`  |   more body formats? 
action_result.data.\*.toRecipients.\*.emailAddress.address | string |  `email`  |   Test@testdomain.abc.com 
action_result.data.\*.toRecipients.\*.emailAddress.name | string |  |   Test Name 
action_result.data.\*.webLink | string |  `url`  |   https://outlook.office365.com/owa/?ItemID=AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0%2BMMHKonvdoWQcAQSl1b8BFiEmbqZql%2BJiUtwAAAgEbAAAAQSl1b8BFiEmbqZql%2BJiUtwABUH%2FstgAAAA%3D%3D&exvsurl=1&viewmodel=ReadMessageItem 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully moved email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'delete email'
Delete an email

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to delete | string |  `msgoffice365 message id` 
**email_address** |  required  | Email address of the mailbox owner | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.email_address | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.id | string |  `msgoffice365 message id`  |   AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwBGAAAAAADRlY7ewL4xToKRDciQog5UBwBvUzMoUJx2S4nbgxzZWx2PAAAAAAEMAABvUzMoUJx2S4nbgxzZWx2PAAEIbt7NAAA= 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully deleted email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'delete event'
Delete an event from user calendar

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Event ID to delete | string |  `msgoffice365 event id` 
**email_address** |  required  | Email address of the mailbox owner | string |  `email` 
**send_decline_response** |  optional  | Send decline response to the organizer | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.email_address | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.id | string |  `msgoffice365 event id`  |   TestAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwBGAAAAAADRlY7ewL4xToKRDciQog5UBwBvUzMoUJx2S4nbgxzZWx2PAAAAAAEMAABvUzMoUJx2S4nbgxzZWx2PAAEIbt7NAAA= 
action_result.parameter.send_decline_response | boolean |  |   True  False 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully deleted email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get email'
Get an email from the server

Type: **investigate**  
Read only: **True**

If the 'download attachments' parameter is set to true, the action will ingest the '#microsoft.graph.itemAttachment' and '#microsoft.graph.fileAttachment' type of attachments.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to get | string |  `msgoffice365 message id` 
**email_address** |  required  | Email address of the mailbox owner | string |  `email` 
**download_attachments** |  optional  | Download attachments to vault | boolean | 
**extract_headers** |  optional  | Extract email headers | boolean | 
**download_email** |  optional  | Download email to vault | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.download_attachments | boolean |  |   True  False 
action_result.parameter.download_email | boolean |  |   True  False 
action_result.parameter.email_address | string |  `email`  |   test@abc.com 
action_result.parameter.extract_headers | boolean |  |   True  False 
action_result.parameter.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwABS2DpfAAAAA== 
action_result.data.\*.@odata.context | string |  `url`  |   https://abc.test.com/v1.0/$metadata#users('test%40abc.com')/messages/$entity 
action_result.data.\*.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFLoCsS" 
action_result.data.\*.@odata.type | string |  |   #test.abc.eventMessage 
action_result.data.\*.allowNewTimeProposals | string |  |  
action_result.data.\*.attachments.\*.@odata.mediaContentType | string |  |   application/octet-stream 
action_result.data.\*.attachments.\*.@odata.type | string |  |   #test.abc.fileAttachment 
action_result.data.\*.attachments.\*.attachmentType | string |  |   #test.abc.fileAttachment 
action_result.data.\*.attachments.\*.contentId | string |  `email`  |   F5832F4CF6EFEC41B9CBC6DED238A234@namprd18.prod.test.com 
action_result.data.\*.attachments.\*.contentLocation | string |  |  
action_result.data.\*.attachments.\*.contentType | string |  |   text/plain 
action_result.data.\*.attachments.\*.id | string |  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwABS2DpfAAAAAESABAA0EuDIoiFb0ifXM0ETmQMVw== 
action_result.data.\*.attachments.\*.isInline | boolean |  |   True  False 
action_result.data.\*.attachments.\*.itemType | string |  |   #test.abc.message 
action_result.data.\*.attachments.\*.lastModifiedDateTime | string |  |   2017-10-26T01:31:43Z 
action_result.data.\*.attachments.\*.name | string |  |   attachment.txt 
action_result.data.\*.attachments.\*.size | numeric |  |   355 
action_result.data.\*.attachments.\*.vaultId | string |  `sha1`  `vault id`  |   719dbf72d7c0bc89d7e34306c08a0b66191902b9 
action_result.data.\*.bccRecipients.email | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.bccRecipients.name | string |  |   Test Name 
action_result.data.\*.body.content | string |  |   `Have a good time with these.\\r\\n` 
action_result.data.\*.body.contentType | string |  |   text 
action_result.data.\*.bodyPreview | string |  |   Have a good time with these. 
action_result.data.\*.categories | string |  |   Green category 
action_result.data.\*.ccRecipients.email | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.ccRecipients.name | string |  |   Test Domain 
action_result.data.\*.changeKey | string |  |   CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFLoCsS 
action_result.data.\*.conversationId | string |  |   AAQkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAQAEU43FQ-fk5LmOxKoTpmHfw= 
action_result.data.\*.conversationIndex | string |  |   AQHWRVB0TS7xy6ZOSEeEl0ahrRHNfQ== 
action_result.data.\*.createdDateTime | string |  |   2017-10-26T01:31:43Z 
action_result.data.\*.endDateTime.dateTime | string |  |   2022-07-26T09:30:00.0000000 
action_result.data.\*.endDateTime.timeZone | string |  |   UTC 
action_result.data.\*.event.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFLoCsS" 
action_result.data.\*.event.allowNewTimeProposals | boolean |  |   True  False 
action_result.data.\*.event.attendees.\*.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.event.attendees.\*.emailAddress.name | string |  |   Test Name 
action_result.data.\*.event.attendees.\*.status.response | string |  |   none 
action_result.data.\*.event.attendees.\*.status.time | string |  |   0001-01-01T00:00:00Z 
action_result.data.\*.event.attendees.\*.type | string |  |   required 
action_result.data.\*.event.body.content | string |  |   `plain text?\\r\\n` 
action_result.data.\*.event.body.contentType | string |  |   text 
action_result.data.\*.event.bodyPreview | string |  |   plain text? 
action_result.data.\*.event.calendar@odata.associationLink | string |  `url`  |   https://test.abc.com/v1.0/users('test@user.abc.com')/calendars('EXAMPLECALENDERID')/$ref 
action_result.data.\*.event.calendar@odata.navigationLink | string |  `url`  |   https://test.abc.com/v1.0/users('test@user.abc.com')/calendars('EXAMPLECALENDERID') 
action_result.data.\*.event.changeKey | string |  |   CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFQwHj9 
action_result.data.\*.event.createdDateTime | string |  |   0001-01-01T00:00:00Z 
action_result.data.\*.event.end.dateTime | string |  |   0001-01-01T00:00:00.0000000 
action_result.data.\*.event.end.timeZone | string |  |   UTC 
action_result.data.\*.event.hasAttachments | boolean |  |   True  False 
action_result.data.\*.event.hideAttendees | boolean |  |   True  False 
action_result.data.\*.event.iCalUId | string |  |   040000008200E00074C5B7101A82E0080000000074AC2CF9CF5ED8010000000000000000100000005B5B104FC55A6E44BC5C6A093AB7F07C 
action_result.data.\*.event.id | string |  `msgoffice365 event id`  |   AAMkAGYwYmE5NmQ0LWVhOGItNGFhMy05OWNlLTE5MzhjMTE5YWYyMQBGAAAAAACkbmmUA5U5RZwZvvg8zew_BwDWyBbuDx-uTKpJ-DXRPByGAAAA1bxhAAAr0tXr3dtaS5qYgFGhi6QjAAQiOoS2AAA= 
action_result.data.\*.event.importance | string |  |   normal 
action_result.data.\*.event.isAllDay | boolean |  |   False  True 
action_result.data.\*.event.isCancelled | boolean |  |   True  False 
action_result.data.\*.event.isDraft | boolean |  |   True  False 
action_result.data.\*.event.isOnlineMeeting | boolean |  |   True  False 
action_result.data.\*.event.isOrganizer | boolean |  |   True  False 
action_result.data.\*.event.isReminderOn | boolean |  |   True  False 
action_result.data.\*.event.lastModifiedDateTime | string |  |   0001-01-01T00:00:00Z 
action_result.data.\*.event.location.displayName | string |  |   Test 
action_result.data.\*.event.location.locationType | string |  |   default 
action_result.data.\*.event.location.uniqueIdType | string |  |   unknown 
action_result.data.\*.event.occurrenceId | string |  |  
action_result.data.\*.event.onlineMeeting.joinUrl | string |  `url`  |   https://test.abc.com/l/meetup-join/19%3ameeting_ZjViMTdlNjEtZjYxNi00N2QyLWJmOWYtMGU5MjVjMDM3ZTZl%40thread.v2/0?context=%7b%22Tid%22%3a%22a417c578-c7ee-480d-a225-d48057e74df5%22%2c%22Oid%22%3a%22e4c722ac-3b83-478d-8f52-c388885dc30f%22%7d 
action_result.data.\*.event.onlineMeetingProvider | string |  |   teamsForBusiness 
action_result.data.\*.event.onlineMeetingUrl | string |  |  
action_result.data.\*.event.organizer.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.event.organizer.emailAddress.name | string |  |   Test Name 
action_result.data.\*.event.originalEndTimeZone | string |  |   UTC 
action_result.data.\*.event.originalStartTimeZone | string |  |   UTC 
action_result.data.\*.event.recurrence | string |  |  
action_result.data.\*.event.reminderMinutesBeforeStart | numeric |  |   0 
action_result.data.\*.event.responseRequested | boolean |  |   True  False 
action_result.data.\*.event.responseStatus.response | string |  |   accepted 
action_result.data.\*.event.responseStatus.time | string |  |   0001-01-01T00:00:00Z 
action_result.data.\*.event.sensitivity | string |  |   normal 
action_result.data.\*.event.seriesMasterId | string |  |  
action_result.data.\*.event.showAs | string |  |   tentative 
action_result.data.\*.event.start.dateTime | string |  |   0001-01-01T00:00:00.0000000 
action_result.data.\*.event.start.timeZone | string |  |   UTC 
action_result.data.\*.event.subject | string |  |   Just wanted to say hello 
action_result.data.\*.event.transactionId | string |  |  
action_result.data.\*.event.type | string |  |   singleInstance 
action_result.data.\*.event.webLink | string |  `url`  |   https://test.abc.com/owa?itemid=AAMkAGYwYmE5NmQ0LWVhOGItNGFhMy05OWNlLTE5MzhjMTE5YWYyMQBGAAAAAACkbmmUA5U5RZwZvvg8zew%2BBwDWyBbuDx%2FuTKpJ%2FDXRPByGAAAA1bxhAAAr0tXr3dtaS5qYgFGhi6QjAAQiOoS2AAA%3D&exvsurl=1&path=/calendar/item 
action_result.data.\*.flag.flagStatus | string |  |   notFlagged 
action_result.data.\*.from.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.from.emailAddress.name | string |  `email`  |   Test Name 
action_result.data.\*.hasAttachments | boolean |  |   True  False 
action_result.data.\*.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwABS2DpfAAAAA== 
action_result.data.\*.importance | string |  |   normal 
action_result.data.\*.inferenceClassification | string |  |   focused 
action_result.data.\*.internetMessageHeaders.ARC-Authentication-Results | string |  |   i=1; mx.test.com 1; spf=pass smtp.mailfrom=user.test.com; dmarc=pass action=none header.from=user.abc.com; dkim=pass header.d=test.abc.com; arc=none 
action_result.data.\*.internetMessageHeaders.ARC-Message-Signature | string |  |   i=1; a=rsa-sha256; c=relaxed/relaxed; d=test.com; s=arcselector9901; h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1; bh=3fZ/7Rn8nzby4BCiwxGpfUUiHgfvSZ6MOHtHg1Hmixs=; b=f7VAkSO/T2NJuxMrJNBzeow/t2iTVZfAkVaZGgtAoYq3Wb9cUDEfAtTE4RmzSqLEqP2iXxLK7JsRfV2uqsbGinp3ZuRnHSqMoRzO0XCN8KjE/Z9hUyUmq05clk2rB3TqCcKK6ipy1+N+4mvCFFb6O+bN/9TGhPos1dY0X0sy33sow9oeND6nm8HvtIzp/hG0xKduPnEHwQiCCwRTmdAtbAzMWmnEyyodRQg/PCgjAPKPpeFELZ+pr/bbEkySxLCu/xY1qhoa8JMIrh1EUFHyFyscTDc580YNnowNqAR//iO8DRGaTG1Znv4MI7mlcmM/vopKYAa6zNPXb2LHDqwKBQ== 
action_result.data.\*.internetMessageHeaders.ARC-Seal | string |  |   i=1; a=rsa-sha256; s=arcselector9901; d=test.com; cv=none; b=GIfa87IhNn+v4Mdn75nJpk9WjELaP8fw9+C+Ey0QFktfU60rPvtJDc5qJS5mN/g6COFa2inOEc4S+Cm3R1BLcBgqkCZR/niPjMp/A2tEHs9OeY75S+T8d5OsfmFcD2jC5/59Dc8EAEKw3UnYKxCC4CKWPFCXrE+Cu3jLEtt04Izr1rXTTQacfCjwYN4OsKI9lHyn6JRDlePR2RZKztMcnt/hcOJz6cwFe+MAUgg0qjKB8p+27o2hQKu+LlQDg8nMRQ6jHkD8DylOclHe2nVKmEhNXi67PTeoqTfZe4+YgSOrnJOUdlra5q/EoWN0FnM9Zt0+0K42ncYSWcC0NpsbqQ== 
action_result.data.\*.internetMessageHeaders.Accept-Language | string |  |   en-US 
action_result.data.\*.internetMessageHeaders.Authentication-Results | string |  |   spf=pass (sender IP is 209.85.210.171) smtp.mailfrom=testdomain.com; .abc.com; dkim=pass (signature was verified) header.d=testdomain.com.20150623.gappssmtp.com;.abc.com; dmarc=pass action=none header.from=testdomain.com;compauth=pass reason=100 
action_result.data.\*.internetMessageHeaders.Authentication-Results-Original | string |  |   dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=test.abc.com; 
action_result.data.\*.internetMessageHeaders.Content-Language | string |  |   en-US 
action_result.data.\*.internetMessageHeaders.Content-Transfer-Encoding | string |  |   binary 
action_result.data.\*.internetMessageHeaders.Content-Type | string |  |   multipart/related 
action_result.data.\*.internetMessageHeaders.DKIM-Signature | string |  |   v=1; a=rsa-sha256; c=relaxed/relaxed;        d=testdomain.com.20150623.gappssmtp.com; s=20150623;        h=message-id:date:mime-version:from:to:subject;        bh=tlTaRbacq4aWozhUPvcWg8i8flbpYQGZNs27nncn83I=;        b=avAAeJ8jF08K4oIBhxTirRmyB+SXHwdU0zdxv7eqs/zWaWWcgmT0007KP560TTgo5u         oD4nb6TvKxpRyWW4QwmkbuMIwHsMvehd2l1gispV3AawyGJjpmN7ErVYfLtIkz2Tap3V         YxmluV+SqeyyxTU8pFAEZ7+2C2lOb1DO5TC7xCMv+dyzevSscJdbeN0dFkG+C93zCqkg         w2fxubx2HDD7b/U6m2wXllYhH608wKJ/qYzyvQyqxYqNiQOtPRg2gw4sZ2UgN3+UQyVq         8ubO39ZuqakJpzEzYMw10d6E7SQhvHDJH7mFwhBlzhvOpb2gLJDN8n8dJaZo05BozQqq         MsvA== 
action_result.data.\*.internetMessageHeaders.Date | string |  |   Thu, 18 Jun 2020 02:11:26 -0700 
action_result.data.\*.internetMessageHeaders.From | string |  |   "Test" <test@abc.def.com> 
action_result.data.\*.internetMessageHeaders.In-Reply-To | string |  |   <DM6QE11MB40266715C3C22ACE4E45D182D9730@DM6PR11MB4026.namprd11.prod.test.com> 
action_result.data.\*.internetMessageHeaders.MIME-Version | string |  |   1.0 
action_result.data.\*.internetMessageHeaders.Message-ID | string |  |   <5eeb2fbe.1c69fb81.22b4b.676a@mx.test.com> 
action_result.data.\*.internetMessageHeaders.Received | string |  |   from localhost.localdomain (host-240.test.com. [204.107.141.240])        by test.abc.com with UTF8SMTPSA id ng12sm1923252pjb.15.2020.06.18.02.11.26        for <test@abc.com>        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);        Thu, 18 Jun 2020 02:11:26 -0700 (PDT) 
action_result.data.\*.internetMessageHeaders.Received-SPF | string |  |   Pass (protection.test.com: domain of testdomain.com designates 209.85.210.171 as permitted sender) receiver=protection.test.com; client-ip=209.85.210.171; helo=mail-pf1-f171.test.com; 
action_result.data.\*.internetMessageHeaders.References | string |  |   <DM6PR11MB40266715C3C33BCE4E45D182D9730@DM6PR11MB4026.namprd11.prod.test.com> 
action_result.data.\*.internetMessageHeaders.Return-Path | string |  `email`  |   notifications@testdomain.com 
action_result.data.\*.internetMessageHeaders.Subject | string |  |   Fw: Email having different attachments 
action_result.data.\*.internetMessageHeaders.Thread-Index | string |  |   AQDEZLqyXR4k4Sc6skyFCMPITcMsbKpGS7At 
action_result.data.\*.internetMessageHeaders.Thread-Topic | string |  |   Email having different attachments 
action_result.data.\*.internetMessageHeaders.To | string |  |   "Test" <test@abc.def.com> 
action_result.data.\*.internetMessageHeaders.X-EOPAttributedMessage | string |  |   0 
action_result.data.\*.internetMessageHeaders.X-EOPTenantAttributedMessage | string |  |   a417c578-c7ee-480d-a225-d48057e74df5:0 
action_result.data.\*.internetMessageHeaders.X-Forefront-Antispam-Report | string |  |   CIP:209.85.210.171;CTRY:US;LANG:en;SCL:-1;SRV:;IPV:NLI;SFV:SFE;H:mail-pf1-f171.test.com;PTR:mail-pf1-f171.test.com;CAT:NONE;SFTY:;SFS:;DIR:INB;SFP:; 
action_result.data.\*.internetMessageHeaders.X-Forefront-Antispam-Report-Untrusted | string |  |   CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BYAPR18MB2408.namprd18.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(136003)(396003)(346002)(39830400003)(376002)(366004)(186003)(83380400001)(64756008)(76116006)(66946007)(71200400001)(8676002)(66476007)(66446008)(66556008)(6916009)(55016003)(91956017)(9686003)(41300700001)(6506007)(7696005)(26005)(2906002)(33656002)(38070700005)(86362001)(38100700002)(3480700007)(122000001)(5660300002)(4744005)(316002)(296002)(166002)(478600001)(8936002)(52536014);DIR:OUT;SFP:1102; 
action_result.data.\*.internetMessageHeaders.X-Gm-Message-State | string |  |   AOAM533ynFERIhSIewEEkj4b8B1rPNOEeie1IxBdrd55treEMtBa1jkL	cO5ee4Ff6p0FYedfFtVtHKiCglGTpFTOSw== 
action_result.data.\*.internetMessageHeaders.X-Google-DKIM-Signature | string |  |   v=1; a=rsa-sha256; c=relaxed/relaxed;        d=1e100.net; s=20161025;        h=x-gm-message-state:message-id:date:mime-version:from:to:subject;        bh=tlTaRbacq4aWozhUPvcWg8i8flbpYQGZNs27nncn83I=;        b=fPT47NIiheeY6GM0bxUOlsmnOgN4WuiOlalFvZqrAiFiOoYk6zrznvgIcAtiHZ4nxE         naQAa+mZs5svqRjib3YI52OvR5U8MitIYaa0Rt3LyYSUO1s3iKTUs4nHyRnqPt1skNl7         2OUwsZPXo3ShJDw/uxZRu/cuN1iIfeuE02PrbR04p4D8+1XRslqt/Xqm/bOWKUauqZWe         dH1E7meFY01hXxODreO4nWHIhsZgr49TpP/OqRyFcyKHHFFg2sPGXz+QNah6jP4YQUYd         Tty2wzOX3nc/YS7TkVo3ORmbzh9o+UZaqH8wHbQlyTdklYxoMPvJwZTo72rTxZeqiJ9E         J7PQ== 
action_result.data.\*.internetMessageHeaders.X-Google-Smtp-Source | string |  |   ABdhPJxrYC7raBubCCIOmauxmxryzS9KsihTN6XCRgaNp2rDrG71TVxryzYCtelFOZ2Xj1LzcYIiMA== 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-AntiSpam-MessageData | string |  |   VSM9HTzub/OH3NCwWNKQqkkzjnhdw5kXsgd9WM0SRgZ0qRdPg5D9/o3LA7lf8ziXc5k0mm9M5mHvFoYePXNXs/MGhGdBGxa/qUQ+FVHA2mDgfPkamJCEZxz//OX/uruTDo+zF4p9D1dQJpnIpx1M75OhuvrHX/BxWWzyAh78DXfF214YHdyFBCYepwl56CS7+fSGQL/r3p+OvWIBnIkISC+HJljSro2k47pPPAkspMhoUkb+zklyENFjez+JcEHYlih2FiNeUO8kb9b7qvlm3zPK98HLspzDh4BojpQ6Ff330iy7nfIK726tCMByxjOdnEQSB9Ua2sbE5gxSeeWL8MB5DHcQSSsXg+sR8w4gXrXLO3meE0lNQKRoAv2b1U0Q+yM0QBqeQWlymZG21bKeuH4gtAFQvfXNjoCtIbBQK1n7ZnL7fI21FJZRcMcKEneus6gLYUqD4PdLEq9FEGbfgiLmVYeUAL2A0Q/gectvL1OVudtHVR5gFMJKt65F1OtS04CPulfLLFSl1F4AzpjjtBSyQcK9R7bOsjoHxQXPMd9fMCzMSIq5f551pO0klKqWY7l11Un2Noj6CA7EtXiD1bTv8JmYQEKR+0HTZagNd+79GeTvKjxTvt9MkyO8k3aqWyNqT331ITnVICtksN1TVMCp8GVeDudNMr2PLSW0alOduR5unuEgTWrqHoaTGOovQx0PVjudNlpZ80ANK9hqaC/ZhLLOtNpJ3fZnjs06PzrPLGhE/IeccY1n8sYDvGm1QA9TN6JaaGPl1Pj6ecy16k0XuF/PKGHTL0M4LCpxSS6T87oFFH1zHkKtmbJp3aAI4bt3ihbQmwFb29JyMgL7ZOy+zrIwXGILh1KQGWQQv1uXXnAuqQy29HeFXs6D2hDHxHlBk5ZQ+vgRtsvRvGnq58vJ3CapjntfL3pOINUj1avLyAZxjasBWMTwaZs9JQ4ZIMekzkIk05lh9XfDSeULk2yKaH8YSCC6ENUHxSWa6pPHJfOdp9kXwOtlp09/VTTAikKy862k9ybN4bRWZB45B9Pv5scna8IX3rthIXUih8c= 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-AntiSpam-MessageData-Original-0 | string |  |   SC/7FB9jcHrfqMtL+8C1Sp2MBDl48qjRn/ZzFJk8+2yWs9kmQwzxXC8TA3HuU0EMts58S8uTyFbx12+qQUJ45/B5QFEfP5j1o7B5kj1Q0C9S+LAg6YptTwxi29Ei1T4mf+CpfzIeA73NzXB7pWjnmycYYlL3TAn0xJATthWspUZ+g4jZoDzNSIdAZWqoc1j4+dHA6WR+U9zZi0vODxRmplSWq2FeO8uMKqD43StpvYk6chxcaGGc5+rNRxP6RLF7OLirJ0MQ1FfZNRdNfUKBvGAF2r6HLp62apGZg0d5gJ5M7zg/1V4ygWW19cuGXyAr5b9bow1MPIOBfrDrMS3CBk2F9DfATTZ/oFwOv/hCUVs2MkWSdr/upJfPt0xoAYtXk1UjxKpV/nHgTTfQy/ijlxEsYn/HY9O6tfqvn/BRvehvPjjoouvxcZteyP1glEcajum7Op67/kV9p4Wv+U+A+31/kyrb3Tjt4GJGpTIBfLi/VjIiHUDFrpAcBz3rFqxyfKQcCqDsOMjD5CrxBj3ow7uMlQiaQoU0Dxwc4eDggbe9Af/F3YqZuvqpj2H0U0hm7+7j56WjFxewVKHLJBwkCXG6a8UdEmKBtA685mUbfpICdYaoLatC4LYOMeqsx6CeEr75vyfdqTdKOZrBKkhTluMbR0s1pvh0kID7B+HL/LKqFSnpgQidfIugk5FUSh42vsBUjrxq6LWYDSHWwYweeuZi/6vVgKQl1XS5X7JUhwNxZSzSF76pNeCIq6KGlCmfIrAnAAhfd0a0xMGy/gOJiqM8JcWjnCMA25UrRL2XrMLC4mnLpi71rATOU62rcgNyczpKI74uHEQAGtQBHfoJjuAqK1JNAK5+j1kIT9gr1F0CC2iJ+68DOI+dveK2lkGqyNYx+eKeTjJSKO4bfzQiM0oBg9eIwqtU3Wn+sSQEg74MzrMjEfaorXh7X+LdO4DwA7dNyEurnYEgmjvjJoNbcxgjhbLSkTe3LFAX7iUia79VIqgD80bxgwoCWyKiSiCKARb/krBWOCOOuF1I6v6azxPHpwsQxC6AvFlOWW7BXsFY9NcCeGvV7l+9ZnLuRjdbjrgdk1b7PRv6aaRzmVk1I3KPBCPvFasP2XhNJXGgYmv7hxiyOci1Eoq4QcXEfr9VsrOEkcl0z4HI8yHx354Lc7Peck8XFvGCe9ElyhxmEtu/ySFQ3BOakjPikOOIA4XlUj3GsUk8qfwnePHVPBnKKm0jtaqjK6tA8uZyKG8jTNgICFZ9wKmsijFMPXVY2lt5zuPnw1V31D//IYjdXpcU1cMfXgZ06vld4anBSEv3WL3zCZaIJsRhxkB7ixumw4h5yieKNJFIVhbV6Ty4Yog9JFmQbAbRfKh1b8ltoym804+hOH8n7oWVqSbtzuylg7DPCIVOcWdUNraXYgmgtXDM6vq0SsDK1j2diz4ywM2BlBSsnCyAdt1NN5gZyMfOufZ3a8SKdwTaRH3bFh6BmfLEZ8NgYbeJQX7GrVbBU5kHT9+k2g3Klchapmqv8mzl0uKvX1av2hW6ce5xo+owa9Qk/Gza4j4o74bVl8tJ/iYClX4kpHY6kek/TOA/Sxj/IvWb1QZvpgmj0LNNCrLdrLUiTDG3lodE9j+Lr8qhmgL8S78= 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-AntiSpam-MessageData-Original-ChunkCount | string |  |   1 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-AuthAs | string |  |   Internal 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-AuthSource | string |  |   SJ0PR22MB4941.namprd11.prod.test.com 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-FromEntityHeader | string |  |   Internet 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-Id | string |  |   a417c578-c7ee-480d-a225-d48057e74df5 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-MailboxType | string |  |   HOSTED 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-Network-Message-Id | string |  |   4b1ef179-4fe7-4248-7ec0-08d81367956e 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-OriginalArrivalTime | string |  |   18 Jun 2020 09:11:28.2511 (UTC) 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-UserPrincipalName | string |  |   bs91VnpEPjrqCnvlIeymwO6ye5P9rggHggVNUPUbV/tC9uuFPVFOYg7e/Cd0MeGmSqT4AlLW0Nn4ZeEqNieSf/D1gp5iLz/YkwjXhYUSJnLRb/csQN4sRMMZsX3LUkKkwVpifaeJzoukLu8qSWn7og== 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-AuthAs | string |  |   Anonymous 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-AuthMechanism | string |  |   04 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-AuthSource | string |  |   DM6NAM11FT055.eop-nam11.prod.protection.test.com 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-ExpirationInterval | string |  |   1:00:00:00.0000000 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-ExpirationIntervalReason | string |  |   OriginalSubmit 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-ExpirationStartTime | string |  |   18 Jun 2020 09:11:28.2531 (UTC) 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-ExpirationStartTimeReason | string |  |   OriginalSubmit 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-MessageDirectionality | string |  |   Incoming 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-Network-Message-Id | string |  |   4b1ef179-4fe7-4248-7ec0-08d81367956e 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-SCL | string |  |   -1 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Processed-By-BccFoldering | string |  |   15.20.3109.017 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Transport-CrossTenantHeadersPromoted | string |  |   DM6NAM11FT064.eop-nam11.prod.protection.test.com 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Transport-CrossTenantHeadersStamped | string |  |   BN6PR18MB1492 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Transport-CrossTenantHeadersStripped | string |  |   DM6NAM11FT064.eop-nam11.prod.protection.test.com 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Transport-EndToEndLatency | string |  |   00:00:02.7417647 
action_result.data.\*.internetMessageHeaders.X-MS-Has-Attach | string |  |   yes 
action_result.data.\*.internetMessageHeaders.X-MS-Office365-Filtering-Correlation-Id | string |  |   4b1ef179-4fe7-4248-7ec0-08d81367956e 
action_result.data.\*.internetMessageHeaders.X-MS-Office365-Filtering-Correlation-Id-Prvs | string |  |   0c3038e5-2c60-453b-188f-08da6ed1ea0c 
action_result.data.\*.internetMessageHeaders.X-MS-Oob-TLC-OOBClassifiers | string |  |   OLM:1728; 
action_result.data.\*.internetMessageHeaders.X-MS-PublicTrafficType | string |  |   Email 
action_result.data.\*.internetMessageHeaders.X-MS-TNEF-Correlator | string |  |   <SJ0PR11CD49418BDA1BB4215EB8B890AED9B59@SJ0PR11MB4941.namprd11.prod.test.com> 
action_result.data.\*.internetMessageHeaders.X-MS-TrafficTypeDiagnostic | string |  |   BN6PR18MB1492: 
action_result.data.\*.internetMessageHeaders.X-Microsoft-Antispam | string |  |   BCL:0; 
action_result.data.\*.internetMessageHeaders.X-Microsoft-Antispam-Mailbox-Delivery | string |  |   wl:1;pcwl:1;ucf:0;jmr:0;auth:0;dest:I;ENG:(750128)(520011016)(520004050)(702028)(944506458)(944626604); 
action_result.data.\*.internetMessageHeaders.X-Microsoft-Antispam-Message-Info | string |  |   La+CSxAnpzVJOXq7njrFPhIbsh0khleSwldy+W8NYDRsoyyPruPIiId4Avama7JyfzrxoExzhLk5pDn2lGPAJIpdcguiDSsDQg5T+iBCJgFeaEJXjhstECMi842/JGawB9WsiGw9Q/PpvjO5H/2fNLlQZVZW3AAQVZSsX3az4iOsv1Ggj4aYZRMKHmPAtniWOEtQD7zAEWC0jIZf613lWy3vxHfb/3+pV9X8zqPqazbyGy5Q14PICSNkKnvIw8rmeqJV8eSHhvR51Lchib6OIN4xOpLWxkSkBTt5B95RUPnpgPvgp2yLo0Q+EYRIabLDQ0kMsv+24+RnFmr9vo2gRNuFusw8iEPsVEQyhfgIWtBtsBpyvyykxcfa6lIdzQhixZH3Tlkdh1kb15wFS3Ooz3CjaWbY8jcUot5l1p08Ypsj6r7CpIo3xE6jE0x/EeUkDK3Fu/Ol0pOsJ1N5W4iJLdjqSQM3l/t9QWlcPhD8s6D7D7JM5OUHCeFEPr7sSL+P/5zTgBaeUvwtZrlQSH2GHc+5gPW8rkwlwJLJftVEid0gO2PUOrzItzME5PXYAcdx++sF3XC1YMPLet/jMpX8T7/z7+hxFxNyifgmGJ+DkNOec7yGkkcLBz6iCaHx7OrRGwDHIcdAtV85wCk3NEDDiKyHivQpwp/gY55W+wkLe7aqSHmFzm1rUSslx+DWz8w2EgSjJxOmf0JkoNKbTFl3FObkocR0lUUQUnETuoAXUqvpWGD5B69W9XXUM8c43ozz2oBZseheSAtkLil3tMIr/CMCMILPX/LdoErNtkmiFXCPqaLFSSeyO61oCMl6Ezndtwp22nwMPUg5ofG0kdqFuTW122umhy9C6h5BcREaLhWclSyqDoZPB9RvkRlI2kTRwuwbuFW3iOMzmVwxLIQH9K5JkxdMvC3hvNpjVgz7Q2ZnEF3xSNqeoWVQvkaIe8rQLUc8s+HMRUmSERGdfSuQJAx47g8PDs9s3rS/ThUSzIaljJPbUgXEnFg/G6h3I/yXLj2Nj2OG50snoI5jJmE4+69YmNwasdDZuYpnuQeFgu11HtsLniDthJdjEJyYC1utZNt9hgA+6JlLnm7Dxb43cSIiW8ev+3X+b2kREj2k/m8fSz7YgtoCB8AkuiVXRaH3EUiq8XCExbbWeynKRgwCZ6bzvfSiT3+cg+QQKPHFc/cgot56ta6X80tjhFodpTQNTE6V6C9QFHJ3JCVhsSzVifJAc8crI5hAcPbKFEIjinENcfpF/8reo2Yr1xFElhoX 
action_result.data.\*.internetMessageHeaders.X-Microsoft-Antispam-Message-Info-Original | string |  |   MTrWp0GiNTxQrZWPlJ6veyKekVjJA0FKYcYQlNCKCrjhAtIn4oDZCbWPNm21Zr7mX+CXhspXNSQSEjpIERhcHIWABmuzCF/vnMr0xwLTzuh2T0si6wgTdha+BdCpnx/kvbN+TMK3rCmD9ro6qHf/v1dTbLKJUZ3Cwfl+LoqJLCkw+T8E7/De1QBlCJrKVGfSztXncKPdvPxC2Qjw/QoPmYp7oFbqW8uwNZX1q8HmAXfLzYPeOuLDE/h4s61EeZGvIY7nBMwm6DwKdTqfmQqy3+BTMfoTaN/82aHLgfBI8V0NbiPVvbKbUU8UOusHZM5H6pzOpZFOSsS7yWz1jpIvKK5CJtNUK5XkOCLxv06yzbWib2abzwEhoLUBHYhJGnwNaIznz/C7a6vZLPe1hNxyLBv0/SyYmt1m9v0vB3TSdSH2V+Ork2OK5nz/r1KcOScedjs14GZpifgjEXiIhK4eJlTkI8LE7HnqXr+82C39t13fqV8L8oRYjGiJJE9wpGJIhMa4PQYwgP0D2cQGrVwuVK2qP01TsSE+NWOXyB8hAYn11K/wCnq4TqtwRbptF9aiw0k45eDHfvB/sBARv37sajixtW4QuFQ3eYI9bVVfllmcpnKj5VUD1mdMAnkgpOCiQSEiSI6Tlo9cEycBulSc4fmocQoev7eUTFw43FDjmRpebuNF0lmm7OcvXgS8jBJSzkbLPrrsqTj1fluowoLjQTQsSPn/LK5LdOdCt7x70/BaweDCm9VdcGgh5Mqe0Qp4GxnBSpS61OCmDYZEkCL5W1A+M7Ah9mANYucdydHU9bLxJBcoi42VIDK6oYaKs3oobr0k1M/dk/pjDT65LuHwsA== 
action_result.data.\*.internetMessageHeaders.X-Microsoft-Antispam-Untrusted | string |  |   BCL:0; 
action_result.data.\*.internetMessageHeaders.X-Originating-IP | string |  |   [5.38.181.162] 
action_result.data.\*.internetMessageHeaders.X-Received | string |  |   by 2002:aa7:84d9:: with SMTP id x25mr2807688pfn.300.1592471487394;        Thu, 18 Jun 2020 02:11:27 -0700 (PDT) 
action_result.data.\*.internetMessageHeaders.subject | string |  |   test html 
action_result.data.\*.internetMessageHeaders.x-ms-exchange-antispam-relay | string |  |   0 
action_result.data.\*.internetMessageHeaders.x-ms-exchange-calendar-series-instance-id | string |  |   BAAAAIIA4AB0xbcQGoLgCAAAAAAhGy3GuqDYAQAAAAAAAAAAEAAAAMqUNBGdAN9NtAV6x5ZM9JU= 
action_result.data.\*.internetMessageHeaders.x-ms-exchange-senderadcheck | string |  |   1 
action_result.data.\*.internetMessageHeaders.x-ms-traffictypediagnostic | string |  |   BYAPR18MB2408:EE_MeetingMessage|BL1PR18MB4325:EE_MeetingMessage|DM6NAM11FT064:EE_|CH0PR11MB5427:EE_ 
action_result.data.\*.internetMessageId | string |  `msgoffice365 internet message id`  |   <CABO4XoP4y0jiKDGWr5yQ=-AwrRC-Vbc4LSNju1-Mroxrwn=Rrg@mail.test.com> 
action_result.data.\*.isAllDay | boolean |  |   True  False 
action_result.data.\*.isDelegated | boolean |  |   True  False 
action_result.data.\*.isDeliveryReceiptRequested | boolean |  |   True  False 
action_result.data.\*.isDraft | boolean |  |   True  False 
action_result.data.\*.isOutOfDate | boolean |  |   True  False 
action_result.data.\*.isRead | boolean |  |   True  False 
action_result.data.\*.isReadReceiptRequested | boolean |  |   True  False 
action_result.data.\*.lastModifiedDateTime | string |  |   2017-10-26T01:31:43Z 
action_result.data.\*.meetingMessageType | string |  |   meetingRequest 
action_result.data.\*.meetingRequestType | string |  |   newMeetingRequest 
action_result.data.\*.parentFolderId | string |  `msgoffice365 folder id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAuAAADyW3X5P7Hb0_MMHKonvdoWQEAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAA 
action_result.data.\*.previousEndDateTime | string |  |  
action_result.data.\*.previousEndDateTime.dateTime | string |  |   2022-05-09T13:30:00.0000000 
action_result.data.\*.previousEndDateTime.timeZone | string |  |   UTC 
action_result.data.\*.previousLocation | string |  |  
action_result.data.\*.previousStartDateTime | string |  |  
action_result.data.\*.previousStartDateTime.dateTime | string |  |   2022-05-09T13:00:00.0000000 
action_result.data.\*.previousStartDateTime.timeZone | string |  |   UTC 
action_result.data.\*.receivedDateTime | string |  |   2017-10-26T01:31:43Z 
action_result.data.\*.recurrence | string |  |  
action_result.data.\*.replyTo | string |  |  
action_result.data.\*.responseRequested | boolean |  |   True  False 
action_result.data.\*.sender.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.sender.emailAddress.name | string |  `email`  |   Test Name 
action_result.data.\*.sentDateTime | string |  |   2017-10-26T01:31:35Z 
action_result.data.\*.startDateTime.dateTime | string |  |   2022-07-26T09:00:00.0000000 
action_result.data.\*.startDateTime.timeZone | string |  |   UTC 
action_result.data.\*.subject | string |  `msgoffice365 subject`  |   more attachments 
action_result.data.\*.toRecipients.\*.emailAddress.address | string |  `email`  |   Test@testdomain.abc.com 
action_result.data.\*.toRecipients.\*.emailAddress.name | string |  |   Test Name 
action_result.data.\*.type | string |  |   singleInstance 
action_result.data.\*.vaultId | string |  |   ff89bab9ec1e063a0f100aa7b0ac5fbc7425ab22 
action_result.data.\*.webLink | string |  `url`  |   https://outlook.office365.com/owa/?ItemID=AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0%2BMMHKonvdoWQcAQSl1b8BFiEmbqZql%2BJiUtwAAAgEMAAAAQSl1b8BFiEmbqZql%2BJiUtwABS2DpfAAAAA%3D%3D&exvsurl=1&viewmodel=ReadMessageItem 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully fetched email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get email properties'
Get non-standard email properties from the server

Type: **investigate**  
Read only: **True**

For a list of possible properties to retrieve, visit https://docs.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0&tabs=http.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to get properties of | string |  `msgoffice365 message id` 
**email_address** |  required  | Email address of the mailbox owner | string |  `email` 
**get_headers** |  optional  | Get email headers | boolean | 
**get_body** |  optional  | Get email body | boolean | 
**get_unique_body** |  optional  | Get unique email body | boolean | 
**get_sender** |  optional  | Get email sender | boolean | 
**properties_list** |  optional  | Other properties to get (comma-separated list) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.email_address | string |  `email`  |   user@abc.com 
action_result.parameter.get_body | boolean |  |   True  False 
action_result.parameter.get_headers | boolean |  |   True  False 
action_result.parameter.get_sender | boolean |  |   True  False 
action_result.parameter.get_unique_body | boolean |  |   True  False 
action_result.parameter.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwADu9Tv8QAAAA== 
action_result.parameter.properties_list | string |  |   subject,receivedDateTime 
action_result.data.\*.@odata.context | string |  `url`  |   https://test.abc.com/v1.0/$metadata#users('user%40.abc.com')/messages(internetMessageHeaders,body,uniqueBody,sender,subject)/$entity 
action_result.data.\*.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAO8DBJl" 
action_result.data.\*.body.content | string |  |   `<html><head>\\r\\n<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><meta content="text/html; charset=utf-8"></head><body><h2>HTML heading</h2>HTML body.</body></html>` 
action_result.data.\*.body.contentType | string |  |   html 
action_result.data.\*.id | string |  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwADu9Tv8QAAAA== 
action_result.data.\*.internetMessageHeaders.Accept-Language | string |  |   en-US 
action_result.data.\*.internetMessageHeaders.Authentication-Results | string |  |   spf=pass (sender IP is 209.85.210.171) smtp.mailfrom=testdomain.com; .abc.com; dkim=pass (signature was verified) header.d=testdomain.com.20150623.gappssmtp.com;.abc.com; dmarc=pass action=none header.from=testdomain.com;compauth=pass reason=100 
action_result.data.\*.internetMessageHeaders.Content-Language | string |  |   en-US 
action_result.data.\*.internetMessageHeaders.Content-Transfer-Encoding | string |  |   binary 
action_result.data.\*.internetMessageHeaders.Content-Type | string |  |   multipart/related 
action_result.data.\*.internetMessageHeaders.DKIM-Signature | string |  |   v=1; a=rsa-sha256; c=relaxed/relaxed;        d=testdomain.com.20150623.gappssmtp.com; s=20150623;        h=message-id:date:mime-version:from:to:subject;        bh=tlTaRbacq4aWozhUPvcWg8i8flbpYQGZNs27nncn83I=;        b=avAAeJ8jF08K4oIBhxTirRmyB+SXHwdU0zdxv7eqs/zWaWWcgmT0007KP560TTgo5u         oD4nb6TvKxpRyWW4QwmkbuMIwHsMvehd2l1gispV3AawyGJjpmN7ErVYfLtIkz2Tap3V         YxmluV+SqeyyxTU8pFAEZ7+2C2lOb1DO5TC7xCMv+dyzevSscJdbeN0dFkG+C93zCqkg         w2fxubx2HDD7b/U6m2wXllYhH608wKJ/qYzyvQyqxYqNiQOtPRg2gw4sZ2UgN3+UQyVq         8ubO39ZuqakJpzEzYMw10d6E7SQhvHDJH7mFwhBlzhvOpb2gLJDN8n8dJaZo05BozQqq         MsvA== 
action_result.data.\*.internetMessageHeaders.Date | string |  |   Thu, 18 Jun 2020 02:11:26 -0700 
action_result.data.\*.internetMessageHeaders.From | string |  |   "Test" <test@abc.def.com> 
action_result.data.\*.internetMessageHeaders.In-Reply-To | string |  |   <DM6QX11MB40266715C3C22ACE4E45D182D9730@DM6PR11MB4026.namprd11.prod.test.com> 
action_result.data.\*.internetMessageHeaders.MIME-Version | string |  |   1.0 
action_result.data.\*.internetMessageHeaders.Message-ID | string |  |   <5eeb2fbe.1c69fb81.22b4b.676a@mx.test.com> 
action_result.data.\*.internetMessageHeaders.Received | string |  |   from localhost.localdomain (host-240.test.com. [204.107.141.240])        by tset.abc.com with UTF8SMTPSA id ng12sm1923252pjb.15.2020.06.18.02.11.26        for <user@test.com>        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);        Thu, 18 Jun 2020 02:11:26 -0700 (PDT) 
action_result.data.\*.internetMessageHeaders.Received-SPF | string |  |   Pass (protection.test.com: domain of testdomain.com designates 209.85.210.171 as permitted sender) receiver=protection.test.com; client-ip=209.85.210.171; helo=mail-pf1-f171.test.com; 
action_result.data.\*.internetMessageHeaders.References | string |  |   <DM6PR11MB40266715C3C22ACE4E45D182D9730@DM6PR11MB4034.namprd11.prod.test.com> 
action_result.data.\*.internetMessageHeaders.Return-Path | string |  `email`  |   notifications@testdomain.com 
action_result.data.\*.internetMessageHeaders.Subject | string |  |   Fw: Email having different attachments 
action_result.data.\*.internetMessageHeaders.Thread-Index | string |  |   AQHWZLqyXR4k4Sc6skyFCMPITcMsbKpGS7Bm 
action_result.data.\*.internetMessageHeaders.Thread-Topic | string |  |   Email having different attachments 
action_result.data.\*.internetMessageHeaders.To | string |  |   "Test" <test@abc.def.com> 
action_result.data.\*.internetMessageHeaders.X-EOPAttributedMessage | string |  |   0 
action_result.data.\*.internetMessageHeaders.X-EOPTenantAttributedMessage | string |  |   a417c578-c7ee-480d-a225-d48057e74df5:0 
action_result.data.\*.internetMessageHeaders.X-Forefront-Antispam-Report | string |  |   CIP:209.85.210.171;CTRY:US;LANG:en;SCL:-1;SRV:;IPV:NLI;SFV:SFE;H:mail-pf1-f171.test.com;PTR:mail-pf1-f171.test.com;CAT:NONE;SFTY:;SFS:;DIR:INB;SFP:; 
action_result.data.\*.internetMessageHeaders.X-Gm-Message-State | string |  |   AOAM533ynFERIhSIewEEkj4b8B1rPNOEeie1IxBdrd55treEMtBa1jkL	cO5ee4Ff6p0FYedfFtVtHKiCglGTpFTOSw== 
action_result.data.\*.internetMessageHeaders.X-Google-DKIM-Signature | string |  |   v=1; a=rsa-sha256; c=relaxed/relaxed;        d=1e100.net; s=20161025;        h=x-gm-message-state:message-id:date:mime-version:from:to:subject;        bh=tlTaRbacq4aWozhUPvcWg8i8flbpYQGZNs27nncn83I=;        b=fPT47NIiheeY6GM0bxUOlsmnOgN4WuiOlalFvZqrAiFiOoYk6zrznvgIcAtiHZ4nxE         naQAa+mZs5svqRjib3YI52OvR5U8MitIYaa0Rt3LyYSUO1s3iKTUs4nHyRnqPt1skNl7         2OUwsZPXo3ShJDw/uxZRu/cuN1iIfeuE02PrbR04p4D8+1XRslqt/Xqm/bOWKUauqZWe         dH1E7meFY01hXxODreO4nWHIhsZgr49TpP/OqRyFcyKHHFFg2sPGXz+QNah6jP4YQUYd         Tty2wzOX3nc/YS7TkVo3ORmbzh9o+UZaqH8wHbQlyTdklYxoMPvJwZTo72rTxZeqiJ9E         J7PQ== 
action_result.data.\*.internetMessageHeaders.X-Google-Smtp-Source | string |  |   ABdhPJxrYC7raBubCCIOmauxmxryzS9KsihTN6XCRgaNp2rDrG71TVxryzYCtelFOZ2Xj1LzcYIiMA== 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-AntiSpam-MessageData | string |  |   VSM9HTzub/OH3NCwKXEQqkkzjnhdw5kXsgd9WM0SRgZ0qRdPg5D9/o3LA7lf8ziXc5k0mm9M5mHvFoYePXNXs/MGhGdBGxa/qUQ+FVHA2mDgfPkamJCEZxz//OX/uruTDo+zF4p9D1dQJpnIpx1M75OhuvrHX/BxWWzyAh78DXfF214YHdyFBCYepwl56CS7+fSGQL/r3p+OvWIBnIkISC+HJljSro2k47pPPAkspMhoUkb+zklyENFjez+JcEHYlih2FiNeUO8kb9b7qvlm3zPK98HLspzDh4BojpQ6Ff330iy7nfIK726tCMByxjOdnEQSB9Ua2sbE5gxSeeWL8MB5DHcQSSsXg+sR8w4gXrXLO3meE0lNQKRoAv2b1U0Q+yM0QBqeQWlymZG21bKeuH4gtAFQvfXNjoCtIbBQK1n7ZnL7fI21FJZRcMcKEneus6gLYUqD4PdLEq9FEGbfgiLmVYeUAL2A0Q/gectvL1OVudtHVR5gFMJKt65F1OtS04CPulfLLFSl1F4AzpjjtBSyQcK9R7bOsjoHxQXPMd9fMCzMSIq5f551pO0klKqWY7l11Un2Noj6CA7EtXiD1bTv8JmYQEKR+0HTZagNd+79GeTvKjxTvt9MkyO8k3aqWyNqT331ITnVICtksN1TVMCp8GVeDudNMr2PLSW0alOduR5unuEgTWrqHoaTGOovQx0PVjudNlpZ80ANK9hqaC/ZhLLOtNpJ3fZnjs06PzrPLGhE/IeccY1n8sYDvGm1QA9TN6JaaGPl1Pj6ecy16k0XuF/PKGHTL0M4LCpxSS6T87oFFH1zHkKtmbJp3aAI4bt3ihbQmwFb29JyMgL7ZOy+zrIwXGILh1KQGWQQv1uXXnAuqQy29HeFXs6D2hDHxHlBk5ZQ+vgRtsvRvGnq58vJ3CapjntfL3pOINUj1avLyAZxjasBWMTwaZs9JQ4ZIMekzkIk05lh9XfDSeULk2yKaH8YSCC6ENUHxSWa6pPHJfOdp9kXwOtlp09/VTTAikKy862k9ybN4bRWZB45B9Pv5scna8IX3rthIXUih8c= 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-AuthAs | string |  |   Internal 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-AuthSource | string |  |   SJ0QA11MB4941.namprd11.prod.test.com 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-FromEntityHeader | string |  |   Internet 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-Id | string |  |   a417c578-c7ee-480d-a225-d48057e74df5 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-MailboxType | string |  |   HOSTED 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-Network-Message-Id | string |  |   4b1ef179-4fe7-4248-7ec0-08d81367956e 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-OriginalArrivalTime | string |  |   18 Jun 2020 09:11:28.2511 (UTC) 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-CrossTenant-UserPrincipalName | string |  |   bs91VnpEPjrqCnvlIeymwO6ye4Q8rggHggVNUPUbV/tC9uuFPVFOYg7e/Cd0MeGmSqT4AlLW0Nn4ZeEqNieSf/D1gp5iLz/YkwjXhYUSJnLRb/csQN4sRMMZsX3LUkKkwVpifaeJzoukLu8qSWn7og== 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-AuthAs | string |  |   Anonymous 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-AuthMechanism | string |  |   04 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-AuthSource | string |  |   DM6NAM11FT055.eop-nam11.prod.protection.test.com 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-ExpirationInterval | string |  |   1:00:00:00.0000000 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-ExpirationIntervalReason | string |  |   OriginalSubmit 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-ExpirationStartTime | string |  |   18 Jun 2020 09:11:28.2531 (UTC) 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-ExpirationStartTimeReason | string |  |   OriginalSubmit 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-MessageDirectionality | string |  |   Incoming 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-Network-Message-Id | string |  |   4b1ef179-4fe7-4248-7ec0-08d81367956e 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Organization-SCL | string |  |   -1 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Processed-By-BccFoldering | string |  |   15.20.3109.017 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Transport-CrossTenantHeadersStamped | string |  |   BN6PR18MB1492 
action_result.data.\*.internetMessageHeaders.X-MS-Exchange-Transport-EndToEndLatency | string |  |   00:00:02.7417647 
action_result.data.\*.internetMessageHeaders.X-MS-Has-Attach | string |  |   yes 
action_result.data.\*.internetMessageHeaders.X-MS-Office365-Filtering-Correlation-Id | string |  |   4b1ef179-4fe7-4248-7ec0-08d81367956e 
action_result.data.\*.internetMessageHeaders.X-MS-Oob-TLC-OOBClassifiers | string |  |   OLM:1728; 
action_result.data.\*.internetMessageHeaders.X-MS-PublicTrafficType | string |  |   Email 
action_result.data.\*.internetMessageHeaders.X-MS-TNEF-Correlator | string |  |   <SJ0QM11MB49418BDA1BB4215EB8B890AED9B59@SJ0PR11MB4941.namprd11.prod.test.com> 
action_result.data.\*.internetMessageHeaders.X-MS-TrafficTypeDiagnostic | string |  |   BN6PR18MB1492: 
action_result.data.\*.internetMessageHeaders.X-Microsoft-Antispam | string |  |   BCL:0; 
action_result.data.\*.internetMessageHeaders.X-Microsoft-Antispam-Mailbox-Delivery | string |  |   wl:1;pcwl:1;ucf:0;jmr:0;auth:0;dest:I;ENG:(750128)(520011016)(520004050)(702028)(944506458)(944626604); 
action_result.data.\*.internetMessageHeaders.X-Microsoft-Antispam-Message-Info | string |  |   La+CSxAnpzVJOXq7njrFPhIbsh0khleSwldy+W8NYDRsoyyPruPIiId4Avama7JyfzrxoExzhLk5pDn2lGPAJIpdcguiDSsDQg5T+iBCJgFeaEJXjhstECMi842/JGawB9WsiGw9Q/PpvjO5H/2fNLlQZVZW3AAQVZSsX3az4iOsv1Ggj4aYZRMKHmPAtniWOEtQD7zAEWC0jIZf613lWy3vxHfb/3+pV9X8zqPqazbyGy5Q14PICSNkKnvIw8rmeqJV8eSHhvR51Lchib6OIN4xOpLWxkSkBTt5B95RUPnpgPvgp2yLo0Q+EYRIabLDQ0kMsv+24+RnFmr9vo2gRNuFusw8iEPsVEQyhfgIWtBtsBpyvyykxcfa6lIdzQhixZH3Tlkdh1kb15wFS3Ooz3CjaWbY8jcUot5l1p08Ypsj6r7CpIo3xE6jE0x/EeUkDK3Fu/Ol0pOsJ1N5W4iJLdjqSQM3l/t9QWlcPhD8s6D7D7JM5OUHCeFEPr7sSL+P/5zTgBaeUvwtZrlQSH2GHc+5gPW8rkwlwJLJftVEid0gO2PUOrzItzME5PXYAcdx++sF3XC1YMPLet/jMpX8T7/z7+hxFxNyifgmGJ+DkNOec7yGkkcLBz6iCaHx7OrRGwDHIcdAtV85wCk3NEDDiKyHivQpwp/gY55W+wkLe7aqSHmFzm1rUSslx+DWz8w2EgSjJxOmf0JkoNKbTFl3FObkocR0lUUQUnETuoAXUqvpWGD5B69W9XXUM8c43ozz2oBZseheSAtkLil3tMIr/CMCMILPX/LdoErNtkmiFXCPqaLFSSeyO61oCMl6Ezndtwp22nwMPUg5ofG0kdqFuTW122umhy9C6h5BcREaLhWclSyqDoZPB9RvkRlI2kTRwuwbuFW3iOMzmVwxLIQH9K5JkxdMvC3hvNpjVgz7Q2ZnEF3xSNqeoWVQvkaIe8rQLUc8s+HMRUmSERGdfSuQJAx47g8PDs9s3rS/ThUSzIaljJPbUgXEnFg/G6h3I/yXLj2Nj2OG50snoI5jJmE4+69YmNwasdDZuYpnuQeFgu11HtsLniDthJdjEJyYC1utZNt9hgA+6JlLnm7Dxb43cSIiW8ev+3X+b2kREj2k/m8fSz7YgtoCB8AkuiVXRaH3EUiq8XCExbbWeynKRgwCZ6bzvfSiT3+cg+QQKPHFc/cgot56ta6X80tjhFodpTQNTE6V6C9QFHJ3JCVhsSzVifJAc8crI5hAcPbKFEIjinENcfpF/8reo2Yr1xFElhoX 
action_result.data.\*.internetMessageHeaders.X-Originating-IP | string |  |   [2.39.180.162] 
action_result.data.\*.internetMessageHeaders.X-Received | string |  |   by 2002:aa7:84d9:: with SMTP id x25mr2807688pfn.300.1592471487394;        Thu, 18 Jun 2020 02:11:27 -0700 (PDT) 
action_result.data.\*.internetMessageHeaders.subject | string |  |   test html 
action_result.data.\*.receivedDateTime | string |  |   2020-06-18T09:11:31Z 
action_result.data.\*.sender.emailAddress.address | string |  `email`  |   notifications@testdomain.com 
action_result.data.\*.sender.emailAddress.name | string |  `email`  |   notifications@testdomain.com 
action_result.data.\*.subject | string |  |   test html 
action_result.data.\*.uniqueBody.content | string |  |   <html><body><div>\\r\\n<div>\\r\\n<h2>HTML heading</h2>\\r\\nHTML body.</div>\\r\\n</div>\\r\\n</body></html> 
action_result.data.\*.uniqueBody.contentType | string |  |   html 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully fetched email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'run query'
Search emails

Type: **investigate**  
Read only: **True**

If the <b>query</b> or <b>internet_message_id</b> parameters are included, the <b>subject</b>, <b>sender</b>, <b>body</b>, and <b>range</b> parameters will be ignored. The <b>internet_message_id</b> parameter will take precedence over the <b>query</b> parameter.<br><br>For information on formatting the <b>query</b> parameter, see https://developer.microsoft.com/en-us/graph/docs/concepts/query_parameters.<br><br>If the <b>limit</b> parameter is not included, the action will default to limiting to ten emails that match the rest of the query. The <b>get_folder_id</b> parameter should be enabled only when you specified folder name/folder path in the folder parameter. If you provide folder ID in the <b>folder</b> parameter and set <b>get_folder_id</b> parameter to true, it will throw an error of folder ID not found for given folder name (because the action considers folder parameter value as folder name/folder path). The <b>folder</b> parameter must be either a (case sensitive) well-known name [list here; https://docs.microsoft.com/en-us/graph/api/resources/mailfolder?view=graph-rest-1.0] or the internal o365 folder ID. The action supports searching for a folder that is nested within another. To copy in such a folder, specify the complete folder path using the <b>'/'</b> (forward slash) as the separator.<br>e.g. to search in a folder named <i>phishing</i> which is nested within (is a child of) <i>Inbox</i>, set the value as <b>Inbox/phishing</b>. If a folder name has a literal forward slash('/') in the name escape it with a backslash('\\') to differentiate.<br>When the <b>search_well_known_folders</b> parameter is set to true, action will ignore values provided in the <b>folder</b> and <b>get_folder_id</b> parameters and the user will get details from all 17 well-known folders which are listed below:<br><ul style="columns: 2;-webkit-columns: 2; -moz-columns: 2"> <li>Archive</li> <li>Clutter</li> <li>Conflicts</li> <li>Conversation History</li> <li>Deleted Items</li> <li>Drafts</li> <li>Inbox</li> <li>Junk Email</li> <li>Local Failures</li> <li>Msg Folder Root</li> <li>Outbox</li> <li>Recoverable Items Deletions</li> <li>Scheduled</li> <li>Search Folders</li> <li>Sent Items</li> <li>Server Failures</li> <li>Sync Issues</li></ul><br>If the <b>limit</b> parameter is provided, the user will get the number of messages provided in the <b>limit</b> from every folder if present.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** |  required  | User's email (mailbox to search in) | string |  `email` 
**folder** |  optional  | Destination folder; this must be either a (case-sensitive) well-known name or the internal o365 folder ID | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  `msgoffice365 folder id` 
**search_well_known_folders** |  optional  | Checks all well known folders for messages, ignores folder name provided in parameter | boolean | 
**get_folder_id** |  optional  | Assume the folder parameter contains a folder name/folder path, separated by '/'(forward slash) ; i.e. Inbox/dir1/dir2/dir3. If this parameter is enabled, it retrieves the folder ID for the provided folder name/folder path automatically and replaces the parameter value | boolean | 
**subject** |  optional  | Substring to search in subject | string |  `msgoffice365 subject` 
**body** |  optional  | Substring to search in body | string | 
**sender** |  optional  | Sender email address to match | string |  `email` 
**limit** |  optional  | Maximum emails to return | numeric | 
**query** |  optional  | MS Graph query string | string | 
**internet_message_id** |  optional  | Internet message ID | string |  `msgoffice365 internet message id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.body | string |  |   How are you doing this fine evening? 
action_result.parameter.email_address | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.folder | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  `msgoffice365 folder id`  |   Archive 
action_result.parameter.get_folder_id | boolean |  |   True  False 
action_result.parameter.internet_message_id | string |  `msgoffice365 internet message id`  |   <CAGUkOupas2JehJhTVYEK4qdwfLHOrGTHWAgAUZUoMfo5M7BZ_5N_w@mail.test.com> 
action_result.parameter.limit | numeric |  |   5 
action_result.parameter.query | string |  |   $filter=contains(subject,'Urgent') 
action_result.parameter.search_well_known_folders | boolean |  |   True  False 
action_result.parameter.sender | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.subject | string |  `msgoffice365 subject`  |   Just wanted to say hello 
action_result.data.\*.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFOpxtE" 
action_result.data.\*.@odata.type | string |  |   #test.abc.eventMessageRequests 
action_result.data.\*.allowNewTimeProposals | string |  |  
action_result.data.\*.bccRecipients.\*.emailAddress.address | string |  |   test3.test@test.com 
action_result.data.\*.bccRecipients.\*.emailAddress.name | string |  |   test3.test@test.com 
action_result.data.\*.bccRecipients.email | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.bccRecipients.name | string |  |   Test Name 
action_result.data.\*.body.content | string |  |   `<html>\\r\\n<head>\\r\\n<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\\r\\n<meta content="text/html; charset=iso-8859-1">\\r\\n<style type="text/css" style="display:none">\\r\\n<!--\\r\\np\\r\\n	{margin-top:0;\\r\\n	margin-bottom:0}\\r\\n-->\\r\\n</style>\\r\\n</head>\\r\\n<body dir="ltr">\\r\\n<div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">\\r\\nTest<br>\\r\\n</div>\\r\\n</body>\\r\\n</html>\\r\\n` 
action_result.data.\*.body.contentType | string |  |   text 
action_result.data.\*.bodyPreview | string |  |   How are you doing this fine evening? 
action_result.data.\*.categories | string |  |  
action_result.data.\*.ccRecipients.\*.emailAddress.address | string |  |   test3.test@test.com 
action_result.data.\*.ccRecipients.\*.emailAddress.name | string |  |   test3.test@test.com 
action_result.data.\*.ccRecipients.email | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.ccRecipients.name | string |  |   Test Name 
action_result.data.\*.changeKey | string |  |   CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFOpxtE 
action_result.data.\*.conversationId | string |  |   AAQkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAQAGqbDRkVLxZMtetM-dKqAPo= 
action_result.data.\*.conversationIndex | string |  |   AQHXHRZ01/QE6F/kQkdaSwXyspIYQagZQ== 
action_result.data.\*.createdDateTime | string |  |   2017-10-30T22:32:42Z 
action_result.data.\*.endDateTime.dateTime | string |  |   2020-08-15T12:30:00.0000000 
action_result.data.\*.endDateTime.timeZone | string |  |   UTC 
action_result.data.\*.flag.flagStatus | string |  |   notFlagged 
action_result.data.\*.from.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.from.emailAddress.name | string |  |   Test Name 
action_result.data.\*.hasAttachments | boolean |  |   True  False 
action_result.data.\*.id | string |  `msgoffice365 message id`  |   AAMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAAAAADJbdfk-sdvT4wwcqie92hZBwBBKXVvwEWISZupmqX4mJS3AACEV3zJAABBKXVvwEWISZupmqX4mJS3AAFOZwS4AAA= 
action_result.data.\*.importance | string |  |   normal 
action_result.data.\*.inferenceClassification | string |  |   focused 
action_result.data.\*.internetMessageId | string |  `msgoffice365 internet message id`  |   <CABO4XoM2X=z02-=jmuvtis3MUxHgvTcH7vkVgVC=dwcuN5yT6Q@mail.test.com> 
action_result.data.\*.isAllDay | boolean |  |   True  False 
action_result.data.\*.isDelegated | boolean |  |   True  False 
action_result.data.\*.isDeliveryReceiptRequested | boolean |  |   True  False 
action_result.data.\*.isDraft | boolean |  |   True  False 
action_result.data.\*.isOutOfDate | boolean |  |   True  False 
action_result.data.\*.isRead | boolean |  |   True  False 
action_result.data.\*.isReadReceiptRequested | boolean |  |   True  False 
action_result.data.\*.lastModifiedDateTime | string |  |   2017-10-30T22:32:53Z 
action_result.data.\*.meetingMessageType | string |  |   meetingRequest 
action_result.data.\*.meetingRequestType | string |  |   informationalUpdate 
action_result.data.\*.parentFolderId | string |  `msgoffice365 folder id`  |   AAMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAuAAAAAADJbdfk-sdvT4wwcqie92hZAQBBKXVvwEWISZupmqX4mJS3AACEV3zJAAA= 
action_result.data.\*.previousEndDateTime | string |  |  
action_result.data.\*.previousEndDateTime.dateTime | string |  |   2020-08-15T12:30:00.0000000 
action_result.data.\*.previousEndDateTime.timeZone | string |  |   UTC 
action_result.data.\*.previousLocation | string |  |  
action_result.data.\*.previousStartDateTime | string |  |  
action_result.data.\*.previousStartDateTime.dateTime | string |  |   2020-08-15T12:00:00.0000000 
action_result.data.\*.previousStartDateTime.timeZone | string |  |   UTC 
action_result.data.\*.receivedDateTime | string |  |   2017-10-30T22:32:42Z 
action_result.data.\*.recurrence | string |  |  
action_result.data.\*.replyTo | string |  |  
action_result.data.\*.replyTo.\*.emailAddress.address | string |  |   hellohi@test.com 
action_result.data.\*.replyTo.\*.emailAddress.name | string |  |   hellohi@test.com 
action_result.data.\*.responseRequested | boolean |  |   True  False 
action_result.data.\*.sender.emailAddress.address | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.sender.emailAddress.name | string |  |   Test Name 
action_result.data.\*.sentDateTime | string |  |   2017-10-30T22:32:37Z 
action_result.data.\*.startDateTime.dateTime | string |  |   2020-08-15T12:00:00.0000000 
action_result.data.\*.startDateTime.timeZone | string |  |   UTC 
action_result.data.\*.subject | string |  `msgoffice365 subject`  |   Just wanted to say hello 
action_result.data.\*.toRecipients.\*.emailAddress.address | string |  `email`  |   Test@testdomain.abc.com 
action_result.data.\*.toRecipients.\*.emailAddress.name | string |  |   Test Name 
action_result.data.\*.type | string |  |   singleInstance 
action_result.data.\*.vaultId | string |  `sha1`  `vault id`  |   719dbf72d7c0bc89d7e34306c08a0b66191902b9 
action_result.data.\*.webLink | string |  `url`  |   https://outlook.office365.com/owa/?ItemID=AAMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAAAAADJbdfk%2FsdvT4wwcqie92hZBwBBKXVvwEWISZupmqX4mJS3AACEV3zJAABBKXVvwEWISZupmqX4mJS3AAFOZwS4AAA%3D&exvsurl=1&viewmodel=ReadMessageItem 
action_result.summary.emails_matched | numeric |  |   1 
action_result.message | string |  |   Emails matched: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create folder'
Create a new folder

Type: **generic**  
Read only: **False**

Create a new folder either in the mailbox root or inside an existing folder. The action supports creating a folder that is nested within another. To create in such a folder, specify the complete path using the <b>'/'</b> (forward slash) as the separator.<br>e.g. to search in a folder named <i>phishing</i> which is nested within (is a child of) <i>Inbox</i>, set the value as <b>Inbox/phishing</b>. If a folder name has a literal forward slash('/') in the name escape it with a backslash('\\') to differentiate.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** |  required  | User's email (mailbox to create folders) | string |  `email` 
**folder** |  required  | Folder Name/Path. Use '/'to separate folder elements; i.e. Inbox/dir1/dir2/dir3 | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path` 
**all_subdirs** |  optional  | Make any missing directories in the path if they don't exist instead of failing | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.all_subdirs | boolean |  |   True  False 
action_result.parameter.email_address | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.folder | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  |   Archive 
action_result.data.\*.@odata.context | string |  `url`  |   https://test.abc.com/v1.0/$metadata#users('abc%def.test.com')/mailFolders/$entity 
action_result.data.\*.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAFOpxtE" 
action_result.data.\*.childFolderCount | numeric |  |   1 
action_result.data.\*.displayName | string |  |  
action_result.data.\*.id | string |  `msgoffice365 folder id`  |   AAMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAAAAADJbdfk-sdvT4wwcqie92hZBwBBKXVvwEWISZupmqX4mJS3AACEV3zJAABBKXVvwEWISZupmqX4mJS3AAFOZwS4AAA= 
action_result.data.\*.isHidden | boolean |  |   True  False 
action_result.data.\*.parentFolderId | string |  `msgoffice365 folder id`  |   AAMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQAuAAAAAADJbdfk-sdvT4wwcqie92hZAQBBKXVvwEWISZupmqX4mJS3AACEV3zJAAA= 
action_result.data.\*.sizeInBytes | numeric |  |   0 
action_result.data.\*.totalItemCount | numeric |  |   1 
action_result.data.\*.unreadItemCount | numeric |  |   1 
action_result.summary.folder | string |  |   AQMkAMExNGJmOWQyLTlhMjctNGRiOS1iODU0LTA1ZWE3ZmQ3NDU3MQAuAAADeDDJKaEf4EihMWU6SZgKbAEA07XhOkNngkCkqoNfY_k-jQAFA6de0wAAAA== 
action_result.summary.folders created | numeric |  |   1 
action_result.message | string |  |   Emails matched: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get folder id'
Get the API ID of the folder

Type: **investigate**  
Read only: **True**

The action supports searching a folder that is nested within another. To search in such a folder, specify the complete path using the <b>'/'</b> (forward slash) as the separator.<br>e.g. to search in a folder named <i>phishing</i> which is nested within (is a child of) <i>Inbox</i>, set the value as <b>Inbox/phishing</b>. If a folder name has a literal forward slash('/') in the name escape it with a backslash('\\') to differentiate.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** |  required  | User's email (mailbox) | string |  `email` 
**folder** |  required  | Folder Name/Path. Use '/' to separate folder elements; i.e. Inbox/dir1/dir2/dir3 | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.email_address | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.folder | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  |   Test/Testy/subfolders 
action_result.data.\*.folder | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  |   Test 
action_result.data.\*.folder_id | string |  `msgoffice365 folder id`  |   AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwAuAAAAAADRlY7ewL4xToKRDciQog5UAQBvUzMoUJx2S4nbgxzZWx2PAAEApxCRAAA= 
action_result.data.\*.path | string |  `msgoffice365 mail folder`  `msgoffice365 mail folder path`  |  
action_result.summary.folder_id | string |  `msgoffice365 folder id`  |   AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwAuAAAAAADRlY7ewL4xToKRDciQog5UAQBvUzMoUJx2S4nbgxzZWx2PAAEApxCTAAA= 
action_result.message | string |  |   Folder id: AAMkAGFmNTRhODA4LWIxMjQtNDJjYy05NDM2LWQ5MzY1MGFhMTkzYwAuAAAAAADRlY7ewL4xToKRDciQog5UAQBvUzMoUJx2S4nbgxzZWx2PAAEApxCTAAA= 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'send email'
Sends an email with optional text rendering. Attachments are allowed a Content-ID tag for reference within the html

Type: **generic**  
Read only: **False**

<div><div>Notes</div><ul><li>If the <b>from</b> parameter is not provided, then the action will consider the <b>username</b> parameter provided in the asset configuration as the sender's email address.</li><li>The send email action is executed in two stages. Before sending an email it creates a draft of the email. Once the  draft is successfully saved, the email is sent.</li></ul></div>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**from** |  optional  | From field | string |  `email` 
**to** |  required  | List of recipients email addresses | string |  `email` 
**cc** |  optional  | List of recipients email addresses to include on cc line | string |  `email` 
**bcc** |  optional  | List of recipients email addresses to include on bcc line | string |  `email` 
**subject** |  required  | Message Subject | string | 
**headers** |  optional  | Serialized json dictionary. Additional email headers to be added to the message | string | 
**body** |  required  | Html rendering of message | string | 
**attachments** |  optional  | List of vault ids of files to attach to the email. Vault id is used as content id | string |  `sha1`  `vault id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.attachments | string |  `sha1`  `vault id`  |   da39a3ee5e6b4b0d3255bfef95601890afd80709 
action_result.parameter.bcc | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.body | string |  |   <html><body><p>Have a good time with these.</p></body></html> 
action_result.parameter.cc | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.from | string |  `email`  |   test@testdomain.abc.com 
action_result.parameter.headers | string |  |   {"x-custom-header":"Custom value"} 
action_result.parameter.subject | string |  |   Example subject 
action_result.parameter.to | string |  `email`  |   test@testdomain.abc.com 
action_result.data.\*.@odata.context | string |  `url`  |   https://test.abc.com/v1.0/$metadata#users('user%40.abc.com')/messages(internetMessageHeaders,body,uniqueBody,sender,subject)/$entity 
action_result.data.\*.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAO8DBJl" 
action_result.data.\*.body.content | string |  |   `Have a good time with these.\\r\\n` 
action_result.data.\*.body.contentType | string |  |   html 
action_result.data.\*.bodyPreview | string |  |   Have a good time with these. 
action_result.data.\*.changeKey | string |  |   CQAAABYAAADTteE6Q2eCQKSqg19j6T+NAAYzSv5R 
action_result.data.\*.conversationId | string |  |   AAQkAGYxNGJmOWQyLTlhMjctNGRiOS1iODU0LTA1ZWE3ZmQ3NDU3MQAQAORC3aOpHnZMsHD4-7L40sY= 
action_result.data.\*.conversationIndex | string |  |   AQHZopYz5ELdo6kedkywcPj/svjSxg== 
action_result.data.\*.createdDateTime | string |  |   2023-06-19T10:09:58Z 
action_result.data.\*.flag.flagStatus | string |  |   notFlagged 
action_result.data.\*.from.emailAddress.address | string |  `email`  |   test@test.com 
action_result.data.\*.from.emailAddress.name | string |  |   Ryan Edwards 
action_result.data.\*.hasAttachments | boolean |  |   True  False 
action_result.data.\*.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwADu9Tv8QAAAA== 
action_result.data.\*.importance | string |  |   normal 
action_result.data.\*.inferenceClassification | string |  |   focused 
action_result.data.\*.internetMessageId | string |  `msgoffice365 internet message id`  |   <PH7PR11MB690810916B33B92C7EF5E558D95FA@PH7PR11MB6908.namprd11.prod.test.com> 
action_result.data.\*.isDeliveryReceiptRequested | boolean |  |   True  False 
action_result.data.\*.isDraft | boolean |  |   True  False 
action_result.data.\*.isRead | boolean |  |   True  False 
action_result.data.\*.isReadReceiptRequested | boolean |  |   True  False 
action_result.data.\*.lastModifiedDateTime | string |  |   2023-06-19T10:09:58Z 
action_result.data.\*.parentFolderId | string |  `msgoffice365 folder id`  |   AQMkAGYxNGJmOWQyLTlhMjctNGRiOS1iODU0LTA1ZWE3ZmQ3NDU3MQAuAAADeDDJKaEf4EihMWU6SZgKbAEA07XhOkNngkCkqoNfY_k-jQAAAgEPAAAA 
action_result.data.\*.receivedDateTime | string |  |   2020-06-18T09:11:31Z 
action_result.data.\*.sender.emailAddress.address | string |  `email`  |   notifications@testdomain.com 
action_result.data.\*.sender.emailAddress.name | string |  `email`  |   notifications@testdomain.com 
action_result.data.\*.sentDateTime | string |  |   2023-06-19T10:09:58Z 
action_result.data.\*.subject | string |  |   test html 
action_result.data.\*.toRecipients.\*.emailAddress.address | string |  `email`  |   test@test.com 
action_result.data.\*.toRecipients.\*.emailAddress.name | string |  |   Ryan Edwards 
action_result.data.\*.webLink | string |  |   https://outlook.office365.com/owa/?ItemID=AAkALgAAAAAAHYQDEapmEc2byACqAC%2FEWg0A07XhOkNngkCkqoNfY%2Bk%2FjQAGNNQOowAA&exvsurl=1&viewmodel=ReadMessageItem 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully sent email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'on poll'
Ingest emails from Office 365 using Graph API

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** |  optional  | Parameter Ignored in this app | numeric | 
**end_time** |  optional  | Parameter Ignored in this app | numeric | 
**container_id** |  optional  | Parameter Ignored in this app | string | 
**container_count** |  required  | Maximum number of emails to ingest | numeric | 
**artifact_count** |  optional  | Parameter Ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'update email'
Update an email on the server

Type: **generic**  
Read only: **False**

Currently, this action only updates the categories and subject of an email. To set multiple categories, please pass a comma-separated list to the <b>category</b> parameter.<br>NOTE: If the user tries to update the categories, then the existing categories of the email will be replaced with the new categories provided as input.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Message ID to delete | string |  `msgoffice365 message id` 
**email_address** |  required  | Email address of the mailbox owner | string |  `email` 
**subject** |  optional  | Subject to set | string | 
**categories** |  optional  | Categories to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.categories | string |  |   Yellow, Blue, Purple, red 
action_result.parameter.email_address | string |  `email`  |   test@sample.com 
action_result.parameter.id | string |  `msgoffice365 message id`  |   AAMkAGIyMTUxYTkzLWRjYjctNDFjMi04NTAxLTQzMDFkNDhlZmI5MQBGAAAAAACxQSnX8n2GS4cunBIQ2sV7BwCQhMsoV7EYSJF42ChR9SCxAAAAYCbsAACQhMsoV7EYSJF42ChR9SCxAAAAjh8bAAA= 
action_result.parameter.subject | string |  |   Both value are modified 
action_result.data.\*.@odata.context | string |  `url`  |   https://test.abc.com/v1.0/$metadata#users('user%40.abc.com')/messages(internetMessageHeaders,body,uniqueBody,sender,subject)/$entity 
action_result.data.\*.@odata.etag | string |  |   W/"CQAAABYAAABBKXVvwEWISZupmqX4mJS3AAO8DBJl" 
action_result.data.\*.body.content | string |  |   `Have a good time with these.\\r\\n` 
action_result.data.\*.body.contentType | string |  |   html 
action_result.data.\*.bodyPreview | string |  |   Have a good time with these. 
action_result.data.\*.changeKey | string |  |   CQAAABYAAADTteE6Q2eCQKSqg19j6T+NAAYzSv5R 
action_result.data.\*.conversationId | string |  |   AAQkAGYxNGJmOWQyLTlhMjctNGRiOS1iODU0LTA1ZWE3ZmQ3NDU3MQAQAORC3aOpHnZMsHD4-7L40sY= 
action_result.data.\*.conversationIndex | string |  |   AQHZopYz5ELdo6kedkywcPj/svjSxg== 
action_result.data.\*.createdDateTime | string |  |   2023-06-19T10:09:58Z 
action_result.data.\*.flag.flagStatus | string |  |   notFlagged 
action_result.data.\*.from.emailAddress.address | string |  `email`  |   test@test.com 
action_result.data.\*.from.emailAddress.name | string |  |   Ryan Edwards 
action_result.data.\*.hasAttachments | boolean |  |   True  False 
action_result.data.\*.id | string |  `msgoffice365 message id`  |   AQMkADU3NDk3MzJlLTY3MDQtNDE2Ny1iZDk1LTc4YjEwYzhmZDc5YQBGAAADyW3X5P7Hb0_MMHKonvdoWQcAQSl1b8BFiEmbqZql_JiUtwAAAgEMAAAAQSl1b8BFiEmbqZql_JiUtwADu9Tv8QAAAA== 
action_result.data.\*.importance | string |  |   normal 
action_result.data.\*.inferenceClassification | string |  |   focused 
action_result.data.\*.internetMessageId | string |  `msgoffice365 internet message id`  |   <PH7PR11MB690810916B33B92C7EF5E558D95FA@PH7PR11MB6908.namprd11.prod.test.com> 
action_result.data.\*.isDeliveryReceiptRequested | boolean |  |   True  False 
action_result.data.\*.isDraft | boolean |  |   True  False 
action_result.data.\*.isRead | boolean |  |   True  False 
action_result.data.\*.isReadReceiptRequested | boolean |  |   True  False 
action_result.data.\*.lastModifiedDateTime | string |  |   2023-06-19T10:09:58Z 
action_result.data.\*.parentFolderId | string |  `msgoffice365 folder id`  |   AQMkAGYxNGJmOWQyLTlhMjctNGRiOS1iODU0LTA1ZWE3ZmQ3NDU3MQAuAAADeDDJKaEf4EihMWU6SZgKbAEA07XhOkNngkCkqoNfY_k-jQAAAgEPAAAA 
action_result.data.\*.receivedDateTime | string |  |   2020-06-18T09:11:31Z 
action_result.data.\*.sender.emailAddress.address | string |  `email`  |   notifications@testdomain.com 
action_result.data.\*.sender.emailAddress.name | string |  `email`  |   notifications@testdomain.com 
action_result.data.\*.sentDateTime | string |  |   2023-06-19T10:09:58Z 
action_result.data.\*.subject | string |  |   test html 
action_result.data.\*.toRecipients.\*.emailAddress.address | string |  `email`  |   test@test.com 
action_result.data.\*.toRecipients.\*.emailAddress.name | string |  |   Ryan Edwards 
action_result.data.\*.webLink | string |  |   https://outlook.office365.com/owa/?ItemID=AAkALgAAAAAAHYQDEapmEc2byACqAC%2FEWg0A07XhOkNngkCkqoNfY%2Bk%2FjQAGNNQOowAA&exvsurl=1&viewmodel=ReadMessageItem 
action_result.summary | string |  |  
action_result.message | string |  |   Create time: 2017-10-05T20:19:58Z
Subject: Both value are modified
Sent time: 2017-10-03T21:31:20Z 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'block sender'
Add the sender email into the block list

Type: **contain**  
Read only: **False**

This action takes as input an email whose sender will be added to the Block Senders List. The message ID changes after the execution and is a required parameter for request hence undo action would require unique ID. Note that a message from the email address must exist in the user's mailbox before you can add the email address to or remove it from the Blocked Senders List.<ul><li>If the <b>move_to_junk_folder</b> parameter is set to True, the sender of the target email message is added to the blocked sender list and the email message is moved to the Junk Email folder.</li><li>If the <b>move_to_junk_folder</b> attribute is set to False, the sender of the target email message is added to the blocked sender list and the email message is not moved from the folder.</li></ul>To view the current Block Senders list, please read the following Powershell articles: <ul><li>https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/connect-to-exchange-online-powershell?view=exchange-ps</li><li>https://docs.microsoft.com/en-us/powershell/module/exchange/antispam-antimalware/Get-MailboxJunkEmailConfiguration?view=exchange-ps.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** |  required  | Message ID to pick the sender of | string | 
**user_id** |  required  | User ID to base the action of | string | 
**move_to_junk_folder** |  optional  | Should the email be moved to the junk folder | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.message_id | string |  |  
action_result.parameter.move_to_junk_folder | boolean |  |  
action_result.parameter.user_id | boolean |  |  
action_result.status | string |  |  
action_result.summary | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'unblock sender'
Remove the sender email from the block list

Type: **contain**  
Read only: **False**

This action takes as input an email whose sender will be removed from the Block Senders List. The message ID changes after the execution and is a required parameter for request hence undo action would require unique ID. Note that a message from the email address must exist in the user's mailbox before you can add the email address to or remove it from the Blocked Senders List.<ul><li>If the <b>move_to_inbox</b> parameter is set to True, the sender of the target email message is removed from the blocked sender list and the email message is moved from the Junk Email folder.</li><li>If the <b>move_to_inbox</b> attribute is set to False, the sender of the target email message is removed from the blocked sender list and the email message is not moved from the folder.</li></ul>To view the current Block Senders list, please read the following Powershell articles: <ul><li>https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/connect-to-exchange-online-powershell?view=exchange-ps</li><li>https://docs.microsoft.com/en-us/powershell/module/exchange/antispam-antimalware/Get-MailboxJunkEmailConfiguration?view=exchange-ps.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** |  required  | Message ID to pick the sender of | string | 
**user_id** |  required  | User ID to base the action of | string | 
**move_to_inbox** |  optional  | Should the email be moved to the inbox folder | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.message_id | string |  |  
action_result.parameter.move_to_inbox | boolean |  |  
action_result.parameter.user_id | boolean |  |  
action_result.status | string |  |  
action_result.summary | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'resolve name'
Verify aliases and resolve display names to the appropriate user

Type: **investigate**  
Read only: **True**

Resolve an Alias name or email address, gathering complex data about the user.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Name to resolve | string |  `email`  `string` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.email | string |  `email`  `string`  |  
action_result.data.\*.id | string |  `msgoffice365 id`  |  
action_result.data.\*.userPrincipalName | string |  `msgoffice365 user principal name`  |  
action_result.data.\*.givenName | string |  `msgoffice365 given name`  |  
action_result.data.\*.surname | string |  `msgoffice365 surname`  |  
action_result.data.\*.displayName | string |  `msgoffice365 display name`  |  
action_result.data.\*.mailNickname | string |  `msgoffice365 mail nickname`  |  
action_result.data.\*.mail | string |  `email`  |  
action_result.data.\*.otherMails | string |  `email list`  |  
action_result.data.\*.proxyAddresses | string |  `email list`  |  
action_result.data.\*.jobTitle | string |  `msgoffice365 job title`  |  
action_result.data.\*.officeLocation | string |  `msgoffice365 office location`  |  
action_result.data.\*.value | string |  `msgoffice365 user purpose`  |  
action_result.data.\*.mobilePhone | string |  `msgoffice365 mobile phone`  |  
action_result.data.\*.businessPhones | string |  `msgoffice365 buisness phones`  |  
action_result.data.\*.preferredLanguage | string |  `msgoffice365 preferred language`  |  
action_result.data.\*.state | string |  `msgoffice365 state`  |  
action_result.data.\*.postalCode | string |  `msgoffice365 postal code`  |  
action_result.summary | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  