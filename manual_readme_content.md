## Playbook Backward Compatibility

- With version 3.0.0 of the connector, the 'group_id' parameter of the 'list group members' action has been removed and two new parameters are added in the same action as follows:

  - **method** - Method(Group ID or Group e-mail) using which you want to list group members, by default it is **Group ID**.
  - **identificator** - Value of group id or group e-mail based on the **method** selected.

  Hence, it is requested to please update the existing playbooks by re-inserting
  | modifying | deleting the corresponding action blocks to ensure the correct functioning of the
  playbooks created on the earlier versions of the app.

- The 'id' field of email artifact has been renamed to 'messageId'. Hence, it is requested to the
  end-user to please update their existing playbooks by re-inserting | modifying | deleting the
  corresponding action blocks to ensure the correct functioning of the playbooks created on the
  earlier versions of the app.

## Authentication

This app requires registration of a Microsoft Graph Application. To do so, navigate to the URL
<https://portal.azure.com> in a browser and log in with the Microsoft account, then, click **App
registrations** .

On the next page, select **New registration** and give your app a name.

Once the app is created, follow the below-mentioned steps:

- For authentication using a client secret(OAuth):

  - Under **Certificates & secrets** select **New client secret** . Enter the **Description** and
    select the desired duration in **Expires** . Click on **Add** . Note down this **value**
    somewhere secure, as it cannot be retrieved after closing the window.

- For authentication using certificate based authentication(CBA):

  - Under **Certificates & secrets** select **Certificates** then **Upload Certificate** .
    Select the certifitcate file to upload (.crt/.pem) and enter the **Description** . Note down
    the **thumbprint** as this will be used to configure the asset. ([Certificate Requirements](https://learn.microsoft.com/en-us/azure/databox-online/azure-stack-edge-gpu-certificate-requirements))
  - Generate private key:
    - `openssl genpkey -algorithm RSA -out private_key.pem` / `openssl genrsa -out private_key.pem 2048`
  - Generate certificate from the private key (Valid for 365 days):
    - `openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365`

- Under **Authentication** , select **Add a platform** . In the **Add a platform** window, select
  **Web** . The **Redirect URLs** should be filled right here. We will get **Redirect URLs** from
  the Splunk SOAR asset we create below in the section titled **Splunk SOAR Graph Asset** .

- Under **API Permissions** Click on **Add a permission** .

- Under the **Microsoft API** section, select **Microsoft Graph** .

- To ensure all actions run successfully, Provide the following application permissions to the app:

  - Mail.Read (https://graph.microsoft.com/Mail.Read)

  - Mail.ReadWrite (https://graph.microsoft.com/Mail.ReadWrite)

  - User.Read.All (https://graph.microsoft.com/User.Read.All)

    - For non-admin access, use User.Read (Delegated permission) instead
      (https://graph.microsoft.com/User.Read)

  - Mail.Send (https://graph.microsoft.com/Mail.Send) - It is required only if you want to run
    the **send email** action.

  - Group.Read.All (https://graph.microsoft.com/Group.Read.All) - It is required only if you
    want to run the **list events** action for the group's calendar and for the **list groups**
    and the **list group members** action.

  - Calendar.Read (https://graph.microsoft.com/Calendars.Read) - It is required only if you want
    to run the **list events** action for the user's calendar.

  - Calendars.ReadWrite (https://graph.microsoft.com/Calendars.ReadWrite) - It is required only
    if you want to run the **delete event** action from the user's calendar.

  - MailboxSettings.Read (https://graph.microsoft.com/MailboxSettings.Read) - It is required
    only if you want to run the **oof status** , **list rules** and **get rule** actions.

  - For CBA Authentication, [Application-only access](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes) permissions are required.

- After making these changes, click **Add permissions** , then select **Grant admin consent for
  \<your_organization_name_as_on_azure_portal>** at the bottom of the screen.

- To run a specific action with minimal permissions, please refer to the table below and the given references.

### Action Permissions Table

- Below is the list of required Application/Delegated permissions for successfully running each action in the app. Ensure these permissions are granted to avoid any issues during execution.

- To run a specific action with minimal permissions, please refer below table and the given references.

| Sr.no | Action | Delegated Permissions | Application Permissions |
|-------|--------------------------|---------------------------------|---------------------------------|
| 1 | delete event ([reference](https://learn.microsoft.com/en-us/graph/api/event-delete?view=graph-rest-1.0&tabs=http#permissions)) | Calendars.ReadWrite | Calendars.ReadWrite |
| 2 | oof check ([reference](https://learn.microsoft.com/en-us/graph/api/user-get-mailboxsettings?view=graph-rest-1.0&tabs=http#permissions)) | MailboxSettings.Read | MailboxSettings.Read |
| 3 | list events ([reference](https://learn.microsoft.com/en-us/graph/api/user-list-events?view=graph-rest-1.0&tabs=http)) | Calendars.Read, Group.Read.All (to access groups only) | Calendars.Read (Application permissions not supported for group events) |
| 4 | get rule ([reference](https://learn.microsoft.com/en-us/graph/api/messagerule-get?view=graph-rest-1.0&tabs=http#permissions)) | MailboxSettings.Read | MailboxSettings.Read |
| 5 | list rules ([reference](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messagerules?view=graph-rest-1.0&tabs=http#permissions)) | MailboxSettings.Read | MailboxSettings.Read |
| 6 | list users ([reference](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http)) | User.Read.All, User.ReadBasic.All | User.Read.All |
| 7 | list groups ([reference](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http)) | GroupMember.Read.All, Group.Read.All | GroupMember.Read.All, Group.Read.All |
| 8 | list group members ([reference1](https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http), [reference2](https://learn.microsoft.com/en-us/graph/api/group-list-transitivemembers?view=graph-rest-1.0&tabs=http)) | GroupMember.Read.All, Group.Read.All | GroupMember.Read.All, Group.Read.All |
| 9 | list folders ([reference1](https://learn.microsoft.com/en-us/graph/api/user-list-mailfolders?view=graph-rest-1.0&tabs=http), [reference2](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-childfolders?view=graph-rest-1.0&tabs=http)) | Mail.ReadBasic, Mail.Read | Mail.ReadBasic, Mail.Read |
| 10 | copy email ([reference](https://learn.microsoft.com/en-us/graph/api/message-copy?view=graph-rest-1.0&tabs=http#permissions)) | Mail.ReadWrite | Mail.ReadWrite |
| 11 | move email ([reference](https://learn.microsoft.com/en-us/graph/api/message-move?view=graph-rest-1.0&tabs=http)) | Mail.ReadWrite | Mail.ReadWrite |
| 12 | delete email ([reference](https://learn.microsoft.com/en-us/graph/api/message-delete?view=graph-rest-1.0&tabs=http)) | Mail.ReadWrite | Mail.ReadWrite |
| 13 | get email ([reference1](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0&tabs=http), [reference2](https://learn.microsoft.com/en-us/graph/api/message-list-attachments?view=graph-rest-1.0&tabs=http), [reference3](https://learn.microsoft.com/en-us/graph/api/attachment-get?view=graph-rest-1.0&tabs=http)) | Mail.Read | Mail.Read |
| 14 | get email properties ([reference](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0&tabs=http#permissions)) | Mail.Read, Mail.ReadBasic | Mail.Read, Mail.ReadBasic |
| 15 | run query ([reference1](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messages?view=graph-rest-1.0&tabs=http), [reference2](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0&tabs=http), [reference3](https://learn.microsoft.com/en-us/graph/api/mailfolder-get?view=graph-rest-1.0&tabs=http)) | Mail.Read | Mail.Read |
| 16 | create folder ([reference](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-childfolders?view=graph-rest-1.0&tabs=http)) | Mail.ReadWrite | Mail.ReadWrite |
| 17 | get folder id ([reference](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-childfolders?view=graph-rest-1.0&tabs=http)) | Mail.Read, Mail.ReadBasic | Mail.Read, Mail.ReadBasic |
| 18 | send email ([reference1](https://learn.microsoft.com/en-us/graph/api/message-send?view=graph-rest-1.0&tabs=http), [reference2](https://learn.microsoft.com/en-us/graph/api/attachment-createuploadsession?view=graph-rest-1.0&tabs=http)) | Mail.Send, Mail.ReadWrite | Mail.Send, Mail.ReadWrite |
| 19 | on poll | Mail.Read, Mail.ReadBasic | Mail.Read, Mail.ReadBasic |
| 20 | update email ([reference](https://learn.microsoft.com/en-us/graph/api/eventmessage-update?view=graph-rest-1.0&tabs=http)) | Mail.ReadWrite | Mail.ReadWrite |
| 21 | block sender ([reference](https://learn.microsoft.com/en-us/graph/api/message-markasjunk?view=graph-rest-beta&tabs=http)) | Mail.ReadWrite | Mail.ReadWrite |
| 22 | unblock sender ([reference](https://learn.microsoft.com/en-us/graph/api/message-markasnotjunk?view=graph-rest-beta&tabs=http)) | Mail.ReadWrite | Mail.ReadWrite |
| 23 | resolve name ([reference](https://learn.microsoft.com/en-us/graph/api/user-get-mailboxsettings?view=graph-rest-1.0&tabs=http)) | User.Read, MailboxSettings.Read | User.Read.All, MailboxSettings.Read |
| 24 | get mailbox messages ([reference](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messages?view=graph-rest-1.0&tabs=http)) | Mail.Read | Mail.Read |

## Splunk SOAR Graph Asset

When creating an asset you must choose one of the 3 auth types: **Automatic**, **OAuth**, or **CBA**; and specify your
choice in the **Authentication type to use for connectivity** field. "Automatic" auth means that the app will first try OAuth,
and then if that doesn't work, it will try CBA. For this reason if you choose Automatic auth, the most resilient strategy would be
to specify the parameters required for both OAuth and CBA.

For all three auth types you must fill out the **Application ID** and **Tenant** fields. Both the Application/Client ID and
the Tenant ID can be found in the **Overview** tab on your app's Azure page. After you have these fields filled out click **SAVE**.

After saving, a new field will appear in the **Asset Settings** tab. Take the URL found in the
**POST incoming for MS Graph for Office 365 to this location** field and place it in the **Redirect
URLs** field mentioned in the previous step. To this URL, add **/result** . After doing so the URL
should look something like:

https://\<splunk_soar_host>/rest/handler/msgraphforoffice365_0a0a4087-10e8-4c96-9872-b740ff26d8bb/\<asset_name>/result

Once again, click SAVE at the bottom of the screen.

Additionally, updating the Base URL in the Company Settings is also required. Navigate to
**Administration > Company Settings > Info** to configure the **Base URL For Splunk SOAR** . Then,
select **Save Changes** .

## User Permissions

To complete the authorization process, this app needs permission to view assets, which is not
granted by default. First, navigate to **Asset Settings > Advanced** , to check which user is
listed under **Select a user on behalf of which automated actions can be executed** . By default,
the user will be **automation** , but this user can be changed by clicking **EDIT** at the bottom of
the window. To give this user permission to view assets, follow these steps:

- In the main drop-down menu, select **Administration** , then select the **User Management** ,
  and under that tab, select **Roles & Permissions** . Finally, click **+ ROLE** .
- In the **Add Role** wizard, give the role a name (e.g **Asset Viewer** ), and provide a
  description. Subsequently, under the **Users tab** , click **ADD USERS** to add the user
  assigned to the asset viewed earlier. Then click the **Permissions** tab.
- In the permission tab, under **Basic Permissions** , give the role the **View Assets**
  privilege. Then click **SAVE** .

### Test connectivity

#### Admin User Workflow (OAuth)

- Configure the asset with **Tenant ID**, **Application ID** and **Application Secret** while keeping the **Admin Access Required** as
  checked.
- While configuring the asset for the first time, keep **Admin Consent Already Provided** as
  unchecked.
- The **Redirect URLs** must be configured before executing test connectivity. To configure
  **Redirect URLs** , checkout the section titled **Splunk SOAR Graph Asset** above.
- After setting up the asset and user, click the **TEST CONNECTIVITY** button.
- A window should pop up and display a URL. You will be asked to open the link in a new tab. Open
  the link in the same browser so that you are logged into Splunk SOAR for the redirect. If you
  wish to use a different browser, log in to the Splunk SOAR first, and then open the provided
  link. This new tab will redirect to the Microsoft login page.
- Log in to the Microsoft account with the admin user.
- You will be prompted to agree to the permissions requested by the App.
- Review the requested permissions listed, then click **Accept** .
- If all goes well the browser should instruct you to close the tab.
- Now go back and check the message on the Test Connectivity dialog box, it should say **Test
  Connectivity Passed** .
- For subsequent test connectivity or action runs, you can keep **Admin Consent Already Provided**
  config parameter as checked. This will skip the interactive flow and use the client credentials
  for generating tokens.

#### Non-Admin User Workflow (OAuth)

- Configure the asset with **Tenant ID**, **Application ID** and **Application Secret** while keeping the **Admin Access Required** as
  unchecked. **Admin Consent Already Provided** config parameter will be ignored in the non-admin
  workflow.
- Provide **Access Scope** parameter in the asset configuration. All the actions will get executed
  according to the scopes provided in the **Access Scope** config parameter.
- The **Redirect URLs** must be configured before executing test connectivity. To configure
  **Redirect URLs** , checkout the section titled **Splunk SOAR Graph Asset** above.
- After setting up the asset and user, click the **TEST CONNECTIVITY** button.
- A window should pop up and display a URL. You will be asked to open the link in a new tab. Open
  the link in the same browser so that you are logged into Splunk SOAR for the redirect. If you
  wish to use a different browser, log in to the Splunk SOAR first, and then open the provided
  link. This new tab will redirect to the Microsoft login page.
- Log in to the Microsoft account.
- You will be prompted to agree to the permissions requested by the App.
- Review the requested permissions listed, then click **Accept** .
- If all goes well the browser should instruct you to close the tab.
- Now go back and check the message on the Test Connectivity dialog box, it should say **Test
  Connectivity Passed** .

#### Certificate Based Authentication Workflow (CBA)

- Configure the asset with **Tenant ID**, **Application ID**, **Certificate Thumbprint** and
  the **Certificate Private Key (.PEM).**
- Ensure **Admin Consent Already Provided** is checked.
- After setting up the asset and user, click the **TEST CONNECTIVITY** button.
- Check the message in the Test Connectivity dialog box. it should say **Test
  Connectivity Passed** .

#### Automatic Authentication Workflow

- Configure the asset with both the parameters needed for OAuth and CBA. This means you need to specify either the **Application Secret** or a combination of **Certificate Thumbprint** and **Certificate Private Key (.PEM)**. You may provide all three.
- The OAuth workflow will take priority over the CBA workflow.
- The system doesn’t automatically switch from OAuth to CBA when the **Application Secret** expires. However, if **Admin Access Required** is disabled, **Access Scope** is not specified, and **Admin Consent Already Provided** is enabled, it will switch to CBA upon **Application Secret** expiration.

The app should now be ready to be used.

### On-Poll

**Configuration:**

- email_address - Ingest from the provided email address.
- folder - To fetch the emails from the given folder name (must be provided if running ingestion)
- get_folder_id - Retrieve the folder ID for the provided folder name/folder path automatically
  and replace the folder parameter value.
- first_run_max_emails - Maximum containers to poll for the first scheduled polling (default -
  1000).
- max_containers - Maximum containers to poll after the first scheduled poll completes (default -
  100).
- extract_attachments - Extract all the attachments included in emails.
- extract_urls - Extracts the URLs present in the emails.
- extract_ips - Extracts the IP addresses present in the emails.
- extract_domains - Extract the domain names present in the emails.
- extract_hashes - Extract the hashes present in the emails (MD5).
- ingest_eml - Fetch the EML file content for the 'item attachment' and ingest it into the vault.
  This will only ingest the first level 'item attachment' as an EML file. The nested item
  attachments will not be ingested into the vault. If the extract_attachments flag is set to
  false, then the application will also skip the EML file ingestion regardless of this flag value.
- extract_eml - When polling is on and extract_eml is enabled, it will add the eml files of the
  root email in the vault.

If extract_attachments is set to true, only fileAttachment will be ingested. If both ingest_eml and
extract_attachments are set to true, then both fileAttachment and itemAttachment will be ingested.

## Guidelines to provide folder parameter value

This is applicable to 'on poll', 'copy email', 'move email', and 'run query' actions.

- The **get_folder_id** parameter should be enabled only when you have specified folder
  name/folder path in the **folder** parameter.
- If you provide folder ID in the **folder** parameter and set **get_folder_id** parameter to
  true, it will throw an error of folder ID not found for given folder name (because the action
  considers folder parameter value as folder name/folder path).
- The **folder** parameter must be either a (case sensitive) well-known name (
  <https://docs.microsoft.com/en-us/graph/api/resources/mailfolder?view=graph-rest-1.0> ) or the
  internal o365 folder ID.
- The folder parameter supports nested folder paths. To specify the complete folder path using the
  **'/'** (forward slash) as the separator.\
  e.g. to specify a folder named *phishing* which is nested within (is a child of) *Inbox* , set
  the value as **Inbox/phishing** . If a folder name has a literal forward slash('/') in the name
  escape it with a backslash('\\\\') to differentiate.

## State file permissions

Please check the permissions for the state file as mentioned below.

#### State file path

- For unprivileged instance:
  /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/\<appid>/\<asset_id>\_state.json

#### State file permissions

- File rights: rw-rw-r-- (664) (The Splunk SOAR user should have read and write access for the
  state file)
- File owner: Appropriate Splunk SOAR user

### Note

- An optional parameter **Admin Access Required** has been added to this app. In most cases, this
  should remain checked, as admin access is required for email use cases. If the desired
  integration is to integrate with only one user's calendar, you may consider unchecking this box.
  If unchecked, it allows a non-admin user to provide access to a specific account. This
  functionality will ONLY work with the **list events** functionality. If unchecked, the **Access
  scope** *must* be used. The default scope will work for listing calendar events. Additional
  information on scope can be found
  [here.](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes)
- As per the Microsoft known issues for **Group.Read.All** permission (
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
- If the parameter **Admin Access Required** is unchecked, you have to provide a **scope**
  parameter in the asset configuration. All the actions will get executed according to the scopes
  provided in the **scope** config parameter. The actions will throw an appropriate error if the
  scope of the corresponding permission is not provided by the end-user.
- There is an API limitation that will affect run_query action when providing Unicode values in
  the subject or in the body as parameters and if the result count exceeds 999, the action will
  fail.
- The sensitive values are stored encrypted in the state file.

## Increase the maximum limit for ingestion

The steps are as follows:

1. Open the **/opt/phantom/usr/nginx/conf/conf.d/phantom-nginx-server.conf** file on the SOAR
   instance.
1. Change that value of the **client_max_body_size** variable as per your needs.
1. Save the configuration file.
1. Reload nginx service using **service nginx reload** or try restarting the nginx server from SOAR
   platform: Go to **Administrator->System Health-> System Health** then restart the nginx server.

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Office365 server. Below are the default
ports used by the Splunk SOAR Connector.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |
