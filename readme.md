[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2017-2021 Splunk Inc."
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
## Authentication

This app requires registration of a Microsoft Graph Application. To do so, navigate to the URL
<https://portal.azure.com> in a browser and log in with the Microsoft account, then, click **App
registrations** .  
  
On the next page, select **New registration** and give your app a name.  
  
Once the app is created, follow the below three steps:

-   Under **Certificates & secrets** select **New client secret** . Note down this key somewhere
    secure, as it cannot be retrieved after closing the window.
-   Under **Overview** select **Add a redirect URI** . In the **Add Platform** window, select
    **Web** . The **Redirect URLs** field will be filled in the later steps.
-   Under **API Permissions** the following **Application Permissions** need to be added:
    -   Mail.Read (https://graph.microsoft.com/Mail.Read)

    -   Mail.ReadWrite (https://graph.microsoft.com/Mail.ReadWrite)

    -   User.Read.All (https://graph.microsoft.com/User.Read.All)

          

        -   For non-admin access, use User.Read (Delegated permission) instead
            (https://graph.microsoft.com/User.Read)

    -   Group.Read.All (https://graph.microsoft.com/Group.Read.All)- It is required only if you want
        to run the **list events** action for the group's calendar and for the **list groups**
        action

    -   Calendar.Read (https://graph.microsoft.com/Calendars.Read)- It is required only if you want
        to run the **list events** action for the user's calendar

    -   MailboxSettings.Read (https://graph.microsoft.com/MailboxSettings.Read)- It is required only
        if you want to run the **oof status** action

After making these changes, click **Add permissions** , then select **Grant admin consent for Test
Phantom** at the bottom of the screen.

## Phantom Graph Asset

When creating an asset for the **MS Graph for Office 365** app, place **Application ID** of the app
created during the app registration on the Azure Portal in the **Application ID** field and place
the client secret generated during the app registration process in the **Client Secret** field.
Then, after filling out the **Tenant** field, click **SAVE** . Both the Application/Client ID and
the Tenant ID can be found in the **Overview** tab on your app's Azure page.  
  
After saving, a new field will appear in the **Asset Settings** tab. Take the URL found in the
**POST incoming for MS Graph for Office 365 to this location** field and place it in the **Redirect
URLs** field mentioned in a previous step. To this URL, add **/result** . After doing so the URL
should look something like:  
  

    https://<phantom_host>/rest/handler/msgraphforoffice365_0a0a4087-10e8-4c96-9872-b740ff26d8bb/<asset_name>/result

  
Once again, click save at the bottom of the screen.  

## User Permissions

To complete the authorization process, this app needs permission to view assets, which is not
granted by default. First, under **asset settings** , check which user has listed under **Select a
user on behalf of which automated actions can be executed** . By default, the user will be
**automation** , but this user can be changed by clicking **EDIT** at the bottom of the window. To
give this user permission to view assets, follow these steps:

-   In the main drop-down menu, select **Administration** , then select the **User Management** ,
    and under that tab, select **Roles** . Finally, click **+ ROLE** .
-   In the **Add Role** wizard, give the role a name (e.g **Asset Viewer** ), and provide a
    description. Subsequently, under **Available Users** , add the user assigned to the asset viewed
    earlier. Then click the **Permissions** tab.
-   On the permission tab, under **Available Privileges** , give the role the **View Assets**
    privilege. Then click **SAVE** .

### Test connectivity

After setting up the asset and user, click the **TEST CONNECTIVITY** button. A window should pop up
and display a URL. Navigate to this URL in a separate browser tab. This new tab will redirect to a
Microsoft login page. Log in to a Microsoft account with administrator privileges to the desired
mailboxes. After logging in, review the requested permissions listed, then click **Accept** .
Finally, close that tab. The test connectivity window should show success.  
  
The app should now be ready to be used.  

### On-Poll

**Configuration:**  

-   email_address - Ingest from the provided email address.
-   folder - To fetch the emails from the given folder name (must be provided if running ingestion)
-   first_run_max_emails - Maximum containers to poll for the first scheduled polling (default -
    1000).
-   max_containers - Maximum containers to poll after the first scheduled poll completes (default -
    100).
-   extract_attachments - Extract all the attachments included in emails.
-   extract_urls - Extracts the URLs present in the emails.
-   extract_ips - Extracts the IP addresses present in the emails.
-   extract_domains - Extract the domain names present in the emails.
-   extract_hashes - Extract the hashes present in the emails (MD5).

## State file permissions

Please check the permissions for the state file as mentioned below.

#### State file path

-   For Non-NRI instance: /opt/phantom/local_data/app_states/\<appid>/\<asset_id>\_state.json
-   For NRI instance:
    /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/\<appid>/\<asset_id>\_state.json

#### State file permissions

-   File rights: rw-rw-r-- (664) (The phantom user should have read and write access for the state
    file)
-   File owner: Appropriate phantom user

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
-   If both the checkboxes **Admin Consent Already Provided** and **Admin Access Required** are kept
    as checked while running the test connectivity for the first time, then the test connectivity
    will pass but actions will fail. In order to use the **Admin Consent Already Provided**
    checkbox, first, you need to run the test connectivity with only **Admin Access Required** as
    checked and provide admin consent, and then while running the test connectivity for the second
    time the **Admin Consent Already Provided** should be checked if required. The **checkbox Admin
    Consent Already Provided** is used when running the test connectivity if admin consent is
    already provided.
-   There is an API limitation that will affect run_query action
    when providing Unicode values in the subject or in the body as parameters and if the
    result count exceeds 999, the action will fail.

  
