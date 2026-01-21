# MS Graph for Office 365

Publisher: Splunk <br>
Connector Version: 4.2.1 <br>
Product Vendor: Microsoft <br>
Product Name: Office 365 (MS Graph) <br>
Minimum Product Version: 7.0.0

This app enables MS Graph API-based email ingestion and investigative actions on Office 365

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

## Prerequisites

### Azure AD Admin Role Requirements

To configure this connector, you need appropriate Azure AD administrative privileges. The following roles can perform the required setup tasks:

#### **Required Roles (Least Privilege Options)**

- **Application Administrator** - Can create and manage app registrations, enterprise applications, and grant admin consent for application permissions
- **Cloud Application Administrator** - Similar to Application Administrator but with some limitations on on-premises applications
- **Privileged Role Administrator** - Can grant admin consent for any application permissions
- **Global Administrator** - Has full administrative access

For **least privilege access**, use the **Application Administrator** role, which provides the minimum necessary permissions to:

- Create and configure app registrations
- Upload certificates for Certificate Based Authentication (CBA)
- Configure API permissions
- Grant admin consent for application permissions
- Manage enterprise application settings

## Step-by-Step Configuration

### Step 1: Azure AD App Registration

1. **Create Application**

   - Navigate to [Azure Portal](https://portal.azure.com)
   - Go to **Azure Active Directory** → **App registrations** → **New registration**
   - **Name**: Enter descriptive name (e.g., "SOAR-MSGraph-Connector")
   - **Supported account types**: "Accounts in this organizational directory only"
   - **Redirect URI**: Leave blank (configured later)
   - Click **Register**

1. **Note Required IDs**

   - Copy **Application (client) ID** from Overview page
   - Copy **Directory (tenant) ID** from Overview page
   - Save these values for SOAR asset configuration

### Step 2: Configure Authentication Method

Choose one of the following authentication methods:

#### Option A: OAuth Authentication (Client Secret)

1. **Create Client Secret**
   - Go to **Certificates & secrets** → **New client secret**
   - Enter description and select expiration period
   - Click **Add** and copy the secret value immediately
   - **Important**: Secret cannot be retrieved after closing the window

#### Option B: Certificate Based Authentication (CBA)

1. **Generate Certificate** (if you don't have one)

   \# Generate private key <br>
   `openssl genpkey -algorithm RSA -out private_key.pem`

   \# Generate certificate (valid for 365 days) <br>
   `openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365`

1. **Upload Certificate**

   - Go to **Certificates & secrets** → **Certificates** → **Upload Certificate**
   - Select your certificate file (.crt/.pem)
   - Enter description and note the **thumbprint**

### Step 3: Understanding Microsoft Graph Permissions

Microsoft Graph uses two types of permissions:

#### **Application Permissions** (Recommended for Production)

- **What they are**: Allow the app to access data without a signed-in user
- **When to use**: For automated scenarios, background processing, and admin operations
- **Requires**: Admin consent in Azure AD
- **Scope**: Organization-wide access

#### **Delegated Permissions** (For User-Specific Access)

- **What they are**: Allow the app to act on behalf of a signed-in user
- **When to use**: For interactive scenarios or single-user access
- **Requires**: User consent (and admin consent for high-privilege permissions)
- **Scope**: Limited to what the signed-in user can access

### Step 4: Configure API Permissions

#### **For Test Connectivity (Minimum Required)**

To successfully run Test Connectivity, you need at least one of these permissions:

- **Application**: `User.Read.All` (to verify app can access Graph API)
- **Delegated**: `User.Read` (to verify user authentication)

#### **Permission Categories by Functionality**

**Email Operations**

- `Mail.Read` - Read emails, search messages, polling
- `Mail.ReadWrite` - Copy, move, delete, update emails, create folders
- `Mail.Send` - Send emails with attachments

**User & Group Management**

- `User.Read.All` - List users, resolve names (Application)
- `User.Read` - Basic user info (Delegated)
- `Group.Read.All` - List groups, group members, group calendars

**Calendar Operations**

- `Calendars.Read` - List calendar events
- `Calendars.ReadWrite` - Delete calendar events

**Mailbox Settings**

- `MailboxSettings.Read` - Out-of-office status, mail rules

#### **Add Permissions in Azure AD**

1. Go to **API Permissions** → **Add a permission** → **Microsoft Graph**
1. Choose **Application permissions** (recommended) or **Delegated permissions**
1. Select permissions based on your use case (see Action Permissions Table below)
1. Click **Add permissions**
1. Click **Grant admin consent for [your organization]**
1. Confirm the consent

### Step 5: Configure SOAR Asset

1. **Create Asset in SOAR**

   - Navigate to your SOAR instance
   - Create new asset for "MS Graph for Office 365"
   - Fill in the following required fields:
     - **Tenant**: Directory (tenant) ID from Step 1
     - **Application ID**: Application (client) ID from Step 1
     - **Authentication type**: Choose OAuth, CBA, or Automatic

1. **Configure Authentication Settings**

   **For OAuth:**

   - **Application Secret**: Client secret from Step 2A
   - **Admin Access Required**: Check for admin permissions
   - **Admin Consent Already Provided**: Uncheck initially

   **For CBA:**

   - **Certificate Thumbprint**: From Step 2B
   - **Certificate Private Key (.PEM)**: Your private key content
   - **Admin Consent Already Provided**: Must be checked

   **For Automatic:**

   - Provide both OAuth and CBA parameters
   - OAuth takes priority, falls back to CBA if needed

1. **Configure Redirect URL**

   - Save the asset to generate the POST URL
   - Copy the URL from **POST incoming for MS Graph for Office 365 to this location**
   - Add `/result` to the end of this URL
   - Example: `https://<splunk_soar_host>/rest/handler/msgraphforoffice365_0a0a4087-10e8-4c96-9872-b740ff26d8bb/<asset_name>/result`
   - Go back to Azure Portal → App registrations → Authentication
   - Click **Add a platform** → **Web**
   - Add this complete URL as a redirect URI
   - **Important**: Also configure the Base URL in SOAR at **Administration > Company Settings > Info**

### Step 6: Test Connectivity

#### **What Test Connectivity Does**

Test Connectivity verifies that:

- Your authentication credentials are valid
- SOAR can communicate with Microsoft Graph APIs
- The configured permissions are sufficient
- Network connectivity is working properly

#### **Required Permissions for Test Connectivity**

Test Connectivity needs at least one of these permissions:

- **Application permissions**: `User.Read.All`
- **Delegated permissions**: `User.Read`

#### **OAuth Authentication Flow**

1. **Initial Setup**:

   - Ensure **Admin Consent Already Provided** is **unchecked** for first run
   - Click **TEST CONNECTIVITY**
   - A popup will display an authorization URL

1. **Authorization Process**:

   - Open the URL in a new browser tab (same browser as SOAR)
   - Sign in with your Azure AD admin account
   - Review the requested permissions
   - Click **Accept** to grant consent
   - Close the browser tab when instructed

1. **Verification**:

   - Return to SOAR and check for "Test Connectivity Passed" message
   - For subsequent tests, check **Admin Consent Already Provided** to skip interactive flow

#### **Certificate Based Authentication (CBA) Flow**

1. **Prerequisites**:

   - Ensure **Admin Consent Already Provided** is **checked**
   - Verify certificate thumbprint and private key are correctly configured

1. **Test Process**:

   - Click **TEST CONNECTIVITY**
   - No browser interaction required
   - Check for "Test Connectivity Passed" message

#### **Non-Admin OAuth Flow**

1. **Configuration**:

   - Uncheck **Admin Access Required**
   - Provide **Access Scope** with appropriate permissions
   - Example: `https://graph.microsoft.com/User.Read https://graph.microsoft.com/Calendars.Read`

1. **Test Process**:

   - Follow the same OAuth flow as above
   - User will consent to the specific scopes requested

## Action-Specific Permissions Reference

### Quick Permission Sets

#### **Minimum Set (Test Connectivity Only)**

- **Application**: `User.Read.All`
- **Delegated**: `User.Read`

#### **Email Operations Set**

- **Read-only**: `Mail.Read` + `User.Read.All`
- **Full email management**: `Mail.ReadWrite` + `Mail.Send` + `User.Read.All`

#### **Calendar Operations Set**

- **Read-only**: `Calendars.Read` + `User.Read.All`
- **Full calendar management**: `Calendars.ReadWrite` + `User.Read.All`
- **Group calendars**: `Group.Read.All`

#### **User & Group Management Set**

- **Basic**: `User.Read.All` + `Group.Read.All`
- **Advanced**: Add `GroupMember.Read.All` for detailed group operations

### Detailed Action Permissions Table

| Action | Minimum Required (Del) | Full Functionality (App) | Notes |
|--------|------------------|--------------------|---------|
| **Test Connectivity** | `User.Read.All` (App) or `User.Read` (Del) | Same as minimum | Required for all authentication |
| **Email Actions** | | | |
| get email | `Mail.Read` | `Mail.Read` | Basic email reading |
| get email properties | `Mail.ReadBasic` | `Mail.Read` | ReadBasic for headers only |
| get mailbox messages | `Mail.Read` | `Mail.Read` | Requires read permissions |
| run query | `Mail.Read` | `Mail.Read` | Search emails |
| copy email | `Mail.ReadWrite` | `Mail.ReadWrite` | Requires write permissions |
| move email | `Mail.ReadWrite` | `Mail.ReadWrite` | Requires write permissions |
| delete email | `Mail.ReadWrite` | `Mail.ReadWrite` | Requires write permissions |
| update email | `Mail.ReadWrite` | `Mail.ReadWrite` | Requires write permissions |
| send email | `Mail.Send` | `Mail.Send` + `Mail.ReadWrite` | ReadWrite for attachments |
| block/unblock sender | `Mail.ReadWrite` | `Mail.ReadWrite` | Uses beta API |
| **Folder Actions** | | | |
| list folders | `Mail.ReadBasic` | `Mail.Read` | ReadBasic for folder list only |
| create folder | `Mail.ReadWrite` | `Mail.ReadWrite` | Requires write permissions |
| get folder id | `Mail.ReadBasic` | `Mail.Read` | ReadBasic sufficient |
| **Calendar Actions** | | | |
| list events (user) | `Calendars.Read` | `Calendars.Read` | User calendar only |
| list events (group) | `Group.Read.All` | `Group.Read.All` | App permissions not supported |
| delete event | `Calendars.ReadWrite` | `Calendars.ReadWrite` | Requires write permissions |
| **User/Group Actions** | | | |
| list users | `User.ReadBasic.All` | `User.Read.All` | ReadBasic for basic info only |
| list groups | `Group.Read.All` | `Group.Read.All` | Group information |
| list group members | `GroupMember.Read.All` | `Group.Read.All` | Group membership |
| resolve name | `User.Read` + `MailboxSettings.Read` | `User.Read.All` + `MailboxSettings.Read` | User lookup |
| **Settings Actions** | | | |
| oof check | `MailboxSettings.Read` | `MailboxSettings.Read` | Out-of-office status |
| get rule | `MailboxSettings.Read` | `MailboxSettings.Read` | Mail rules |
| list rules | `MailboxSettings.Read` | `MailboxSettings.Read` | Mail rules |
| **Polling** | | | |
| on poll | `Mail.ReadBasic` | `Mail.Read` | ReadBasic for basic polling |

**Legend**: App = Application permissions, Del = Delegated permissions

**Important Notes**:

- **Test Connectivity**: Always requires at least `User.Read.All` (App) or `User.Read` (Del)
- **Beta APIs**: Block/unblock sender actions use Microsoft Graph beta endpoints
- When you add the scope parameter, multiple scopes are passed as space-separated values. <br>For example: `https://graph.microsoft.com/User.Read https://graph.microsoft.com/Calendars.Read` <br>This means the scopes `User.Read` and `Calendars.Read` are being requested.

## User Permissions Setup

To complete the authorization process, this app needs permission to view assets, which is not granted by default.

1. **Check Asset User**

   - Navigate to **Asset Settings > Advanced**
   - Note the user listed under **Select a user on behalf of which automated actions can be executed**
   - Default user is typically **automation**

1. **Create Asset Viewer Role**

   - Go to **Administration > User Management > Roles & Permissions > + ROLE**
   - **Name**: "Asset Viewer" (or similar)
   - **Users tab**: Add the user from step 1
   - **Permissions tab**: Grant **View Assets** privilege
   - Click **SAVE**

## Polling Configuration

Configure email ingestion with these parameters:

### Required Settings

- **email_address**: Ingest from the provided email address
- **folder**: Folder name/path or Office365 folder ID (required for ingestion)

### Optional Settings

- **get_folder_id**: Auto-retrieve folder ID for provided folder name (default: true)
- **first_run_max_emails**: Maximum containers for first poll (default: 1000)
- **max_containers**: Maximum containers for subsequent polls (default: 100)
- **extract_attachments**: Extract all the attachments included in emails
- **extract_urls**:Extracts the URLs present in the emails
- **extract_ips**: Extracts the IP addresses present in the emails
- **extract_domains**: Extract the domain names present in the emails
- **extract_hashes**: Extract the hashes present in the emails (MD5)
- **ingest_eml**: Fetch the EML file content for the 'item attachment' and ingest it into the vault
  - **Note**: This will only ingest the first level 'item attachment' as an EML file. The nested item attachments will not be ingested into the vault. If the extract_attachments flag is set to false, then the application will also skip the EML file ingestion regardless of this flag value.
- **extract_eml**: When polling is on and extract_eml is enabled, it will add the eml files of the
  root email in the vault

If extract_attachments is set to true, only fileAttachment will be ingested. If both ingest_eml and
extract_attachments are set to true, then both fileAttachment and itemAttachment will be ingested.

### Guidelines to provide folder parameter value

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

## Important Notes

### Authentication Behavior

- **Automatic** authentication tries OAuth first, then falls back to CBA
- OAuth workflow takes priority over CBA when both are configured
- System doesn't auto-switch from OAuth to CBA on secret expiration (except in specific conditions)

### Admin Access Required Parameter

- In most cases, **Admin Access Required** should remain checked for email use cases
- Uncheck only for single-user calendar integration scenarios
- When unchecked, allows non-admin users to provide access to specific accounts
- This functionality ONLY works with **list events** action
- When unchecked, the **Access Scope** parameter must be configured, Additional
  information on scope can be found
  [here.](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes)

### Scope Requirements

- **Admin Access Required** unchecked requires **scope** parameter configuration
- All actions execute according to provided scopes in the **scope** parameter
- Actions will throw appropriate errors if required scope permissions are not provided
- Default scope works for calendar events: `https://graph.microsoft.com/Calendars.Read https://graph.microsoft.com/User.Read`

### API Limitations

- Unicode values in run_query subject/body parameters may fail if results exceed 999 items
- Use more specific search criteria to reduce result count when encountering Unicode issues

### Security

- Sensitive values are stored encrypted in the state file

## State File Permissions

**Path**: `/opt/phantom/local_data/app_states/<appid>/<asset_id>_state.json`

**Required Permissions**:

- File rights: `rw-rw-r--` (664)
- File owner: Splunk SOAR user
- The SOAR user must have read and write access

## Increase the maximum limit for ingestion

The steps are as follows:

\# Edit nginx configuration <br>
`sudo nano /opt/phantom/usr/nginx/conf/conf.d/phantom-nginx-server.conf`

\# Modify client_max_body_size value and save <br>
`client_max_body_size 100M;`

\# Reload nginx <br>
`service nginx reload`

\# or try restarting the nginx server from SOAR platform: Go to Administrator->System Health-> System Health then restart the nginx server.

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Office365 server. Below are the default
ports used by the Splunk SOAR Connector.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

## Microsoft Documentation References

### Core Documentation

- [Microsoft Graph Overview](https://learn.microsoft.com/en-us/graph/overview)
- [Microsoft Graph Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Microsoft Graph API Reference](https://learn.microsoft.com/en-us/graph/api/overview)

### Authentication

- [Application Authentication with Certificates](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)
- [Overview of Permissions and Consent](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)
- [Grant Admin Consent to Applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)

### APIs

- [Outlook Mail API](https://learn.microsoft.com/en-us/graph/api/resources/mail-api-overview)
- [Outlook Calendar API](https://learn.microsoft.com/en-us/graph/api/resources/calendar)

## Asset Configuration Fields

This section explains each configuration field in user-friendly terms.

### Authentication Settings

#### **Tenant** (Required)

- Your organization's Azure AD identifier (GUID format)
- Find in: Azure Portal → Azure Active Directory → Overview → Tenant ID

#### **Application ID** (Required)

- Your registered app's unique identifier in Azure AD (GUID format)
- Find in: Azure Portal → App registrations → [Your App] → Overview

#### **Authentication Type** (Required)

- **OAuth**: Uses client secret (easier setup)
- **CBA**: Uses digital certificate (more secure for production)
- **Automatic**: Tries OAuth first, falls back to CBA

#### **Application Secret** (Required for OAuth)

- Password-like credential for your app (save immediately - cannot retrieve later)
- Find in: Azure Portal → App registrations → [Your App] → Certificates & secrets

#### **Certificate Thumbprint** (Required for CBA)

- Unique fingerprint of your uploaded certificate (hexadecimal string)
- Find in: Azure Portal → App registrations → [Your App] → Certificates & secrets

#### **Certificate Private Key (.PEM)** (Required for CBA)

- Private key matching your uploaded certificate (PEM format, keep secure)

### Access Control Settings

#### **Admin Access Required** (Optional, Default: Checked)

- **Checked**: Application permissions (organization-wide access for automation)
- **Unchecked**: Delegated permissions (user-specific access for single-user scenarios)

#### **Admin Consent Already Provided** (Optional, Default: Unchecked)

- Check after completing admin consent process in Azure AD
- Required when using Certificate Based Authentication

#### **Access Scope** (Required when Admin Access is unchecked)

- Space-separated permission URLs for delegated permissions
- Examples: `https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read`

### Email Polling Settings

#### **Email Address of the User** (Required for On Poll)

- Mailbox to monitor for new emails (e.g., `security@company.com`)

#### **Mailbox Folder** (Optional for On Poll)

- Specific folder to monitor (default: `Inbox`)
- Examples: `SentItems`, `Inbox/Security Alerts`, or folder ID

#### **Retrieve Folder ID Automatically** (Optional, Default: Checked)

- Converts folder names to Office 365 folder IDs for better performance

### Polling Volume Settings

#### **Maximum Containers for First Scheduled Polling** (Optional, Default: 1000)

- Number of emails to ingest during first poll

#### **Maximum Containers for Scheduled Polling** (Optional, Default: 100)

- Number of emails to ingest during each subsequent poll

### Data Extraction Settings

#### **Extract Attachments** - Downloads and stores email attachments in SOAR vault for malware analysis and forensic investigations

#### **Extract Domains** - Finds and creates domain artifacts from email content for DNS-based threat intelligence

#### **Extract EML** - Saves the main email as an EML file in vault to preserve original email format

#### **Extract Hashes** - Finds and creates MD5 hash artifacts from email content for malware identification

#### **Extract IPs** - Finds and creates IP address artifacts from email content for network threat analysis

#### **Extract URLs** - Finds and creates URL artifacts from email content for threat intelligence and phishing analysis

#### **Ingest EML** - Saves attached emails (item attachments) as EML files in vault (requires Extract Attachments enabled)

### Configuration variables

This table lists the configuration variables required to operate MS Graph for Office 365. These variables are specified when configuring a Office 365 (MS Graph) asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant** | required | string | Tenant ID (e.g. 1e309abf-db6c-XXXX-a1d2-XXXXXXXXXXXX) |
**client_id** | required | string | Application ID |
**auth_type** | required | string | Authentication type to use for connectivity |
**client_secret** | optional | password | Application Secret (required for OAuth) |
**certificate_thumbprint** | optional | password | Certificate Thumbprint (required for CBA) |
**certificate_private_key** | optional | password | Certificate Private Key (.PEM) |
**admin_access** | optional | boolean | Admin Access Required |
**admin_consent** | optional | boolean | Admin Consent Already Provided (Required checked for CBA) |
**scope** | optional | string | Access Scope (for use with OAuth non-admin access; space-separated) |
**retry_count** | optional | numeric | Maximum attempts to retry the API call (Default: 3) |
**retry_wait_time** | optional | numeric | Delay in seconds between retries (Default: 60) |
**email_address** | optional | string | Email Address of the User (On Poll) |
**folder** | optional | string | Mailbox folder name/folder path or the internal office365 folder ID to ingest (On Poll) |
**get_folder_id** | optional | boolean | Retrieve the folder ID for the provided folder name/folder path automatically |
**first_run_max_emails** | optional | numeric | Maximum Containers for scheduled polling first time |
**max_containers** | optional | numeric | Maximum Containers for scheduled polling |
**extract_attachments** | optional | boolean | Extract Attachments |
**extract_urls** | optional | boolean | Extract URLs |
**extract_ips** | optional | boolean | Extract IPs |
**extract_domains** | optional | boolean | Extract Domain Names |
**extract_hashes** | optional | boolean | Extract Hashes |
**ingest_eml** | optional | boolean | Ingest EML file for the itemAttachment |
**ingest_manner** | optional | string | How to Ingest |
**extract_eml** | optional | boolean | Extract root (primary) email as Vault |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[on poll](#action-on-poll) - on poll <br>
[block sender](#action-block-sender) - Add a sender to the blocked senders list <br>
[copy email](#action-copy-email) - Copy an email to a folder <br>
[create folder](#action-create-folder) - Create a new mail folder <br>
[delete email](#action-delete-email) - Delete an email <br>
[delete event](#action-delete-event) - Delete an event <br>
[generate token](#action-generate-token) - Generates a new access token <br>
[get email](#action-get-email) - Get an email from the server <br>
[get email properties](#action-get-email-properties) - Get properties of an email <br>
[get folder id](#action-get-folder-id) - Get the ID of a mail folder <br>
[get mailbox messages](#action-get-mailbox-messages) - Get messages from a mailbox folder <br>
[get rule](#action-get-rule) - Get the properties and relationships of a messageRule object <br>
[list events](#action-list-events) - List events from user or group calendar <br>
[list folders](#action-list-folders) - Get the mail folder hierarchy <br>
[list group members](#action-list-group-members) - Get group members <br>
[list groups](#action-list-groups) - List all the groups in an organization, including but not limited to Office 365 groups <br>
[list rules](#action-list-rules) - Get all the messageRule objects defined for the user's inbox <br>
[list users](#action-list-users) - Retrieve a list of users <br>
[move email](#action-move-email) - Move an email to a folder <br>
[oof check](#action-oof-check) - Get user's out of office status <br>
[report message](#action-report-message) - Add the sender email into the report <br>
[resolve name](#action-resolve-name) - Resolve a name to email addresses <br>
[run query](#action-run-query) - Search emails in a mailbox <br>
[send email](#action-send-email) - Send an email <br>
[unblock sender](#action-unblock-sender) - Remove a sender from the blocked senders list <br>
[update email](#action-update-email) - Update properties of an email

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

on poll

Type: **ingest** <br>
Read only: **True**

Callback action for the on_poll ingest functionality

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds). | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds). | numeric | |
**container_count** | optional | Maximum number of container records to query for. | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for. | numeric | |
**container_id** | optional | Comma-separated list of container IDs to limit the ingestion to. | string | |

#### Action Output

No Output

## action: 'block sender'

Add a sender to the blocked senders list

Type: **contain** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** | required | User's email address (mailbox) | string | `email` |
**sender** | required | Email address of sender to block | string | `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.sender | string | `email` | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'copy email'

Copy an email to a folder

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to copy | string | `msgoffice365 message id` |
**email_address** | required | User's email (mailbox to copy from) | string | `email` |
**folder** | required | Destination folder name/path or ID | string | `msgoffice365 folder id` |
**get_folder_id** | optional | Retrieve folder ID from folder name/path | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `msgoffice365 message id` | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.folder | string | `msgoffice365 folder id` | |
action_result.parameter.get_folder_id | boolean | | |
action_result.data.\*.id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.parentFolderId | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create folder'

Create a new mail folder

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** | required | User's email address (mailbox) | string | `email` |
**folder** | required | Name of the folder to create | string | |
**parent_folder** | optional | Parent folder name/path or ID (leave empty for root) | string | |
**get_folder_id** | optional | Retrieve parent folder ID from folder name/path | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.folder | string | | |
action_result.parameter.parent_folder | string | | |
action_result.parameter.get_folder_id | boolean | | |
action_result.data.\*.id | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.parentFolderId | string | | |
action_result.data.\*.childFolderCount | numeric | | |
action_result.data.\*.totalItemCount | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete email'

Delete an email

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to delete | string | `msgoffice365 message id` |
**email_address** | required | User's email (mailbox to delete from) | string | `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `msgoffice365 message id` | |
action_result.parameter.email_address | string | `email` | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete event'

Delete an event

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_id** | required | Event ID to delete | string | `msgoffice365 event id` |
**user_id** | optional | User ID/Principal name | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` |
**group_id** | optional | Group ID | string | `msgoffice365 group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.event_id | string | `msgoffice365 event id` | |
action_result.parameter.user_id | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` | |
action_result.parameter.group_id | string | `msgoffice365 group id` | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'generate token'

Generates a new access token

Type: **generic** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get email'

Get an email from the server

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to get | string | `msgoffice365 message id` |
**email_address** | required | User's email address (mailbox) | string | `email` |
**get_headers** | optional | Get email headers | boolean | |
**download_attachments** | optional | Download attachments | boolean | |
**download_email** | optional | Download email as EML file | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `msgoffice365 message id` | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.get_headers | boolean | | |
action_result.parameter.download_attachments | boolean | | |
action_result.parameter.download_email | boolean | | |
action_result.data.\*.id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.body | string | | |
action_result.data.\*.bodyPreview | string | | |
action_result.data.\*.sender | string | | |
action_result.data.\*.toRecipients | string | | |
action_result.data.\*.ccRecipients | string | | |
action_result.data.\*.bccRecipients | string | | |
action_result.data.\*.receivedDateTime | string | | |
action_result.data.\*.sentDateTime | string | | |
action_result.data.\*.hasAttachments | boolean | | True False |
action_result.data.\*.importance | string | | |
action_result.data.\*.isRead | boolean | | True False |
action_result.data.\*.internetMessageHeaders | string | | |
action_result.data.\*.attachments | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get email properties'

Get properties of an email

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to get | string | `msgoffice365 message id` |
**email_address** | required | User's email address (mailbox) | string | `email` |
**get_headers** | optional | Get email headers | boolean | |
**get_body** | optional | Get email body | boolean | |
**get_unique_body** | optional | Get unique body (without previous replies) | boolean | |
**get_sender** | optional | Get sender information | boolean | |
**download_attachments** | optional | Download attachments | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `msgoffice365 message id` | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.get_headers | boolean | | |
action_result.parameter.get_body | boolean | | |
action_result.parameter.get_unique_body | boolean | | |
action_result.parameter.get_sender | boolean | | |
action_result.parameter.download_attachments | boolean | | |
action_result.data.\*.id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.body | string | | |
action_result.data.\*.uniqueBody | string | | |
action_result.data.\*.bodyPreview | string | | |
action_result.data.\*.sender | string | | |
action_result.data.\*.toRecipients | string | | |
action_result.data.\*.ccRecipients | string | | |
action_result.data.\*.receivedDateTime | string | | |
action_result.data.\*.hasAttachments | boolean | | True False |
action_result.data.\*.internetMessageHeaders | string | | |
action_result.data.\*.attachments | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get folder id'

Get the ID of a mail folder

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID/Principal name | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` |
**folder** | required | Folder name or path (e.g. 'Inbox' or 'Inbox/Subfolder') | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` | |
action_result.parameter.folder | string | | |
action_result.data.\*.folder_id | string | | |
action_result.data.\*.folder_name | string | | |
action_result.data.\*.display_name | string | | |
action_result.data.\*.parent_folder_id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get mailbox messages'

Get messages from a mailbox folder

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** | required | User's email address (mailbox) | string | `email` |
**folder** | optional | Folder name/path or ID | string | |
**get_folder_id** | optional | Retrieve folder ID from folder name/path | boolean | |
**limit** | optional | Maximum number of messages to return | numeric | |
**offset** | optional | Number of messages to skip | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.folder | string | | |
action_result.parameter.get_folder_id | boolean | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.sender | string | | |
action_result.data.\*.receivedDateTime | string | | |
action_result.data.\*.bodyPreview | string | | |
action_result.data.\*.hasAttachments | boolean | | True False |
action_result.data.\*.isRead | boolean | | True False |
action_result.data.\*.importance | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get rule'

Get the properties and relationships of a messageRule object

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID/Principal name | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` |
**rule_id** | required | Inbox rule ID | string | `msgoffice365 rule id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` | |
action_result.parameter.rule_id | string | `msgoffice365 rule id` | |
action_result.data.\*.id | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.sequence | numeric | | |
action_result.data.\*.isEnabled | boolean | | True False |
action_result.data.\*.isReadOnly | boolean | | True False |
action_result.data.\*.hasError | boolean | | True False |
action_result.data.\*.conditions | string | | |
action_result.data.\*.actions | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list events'

List events from user or group calendar

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | optional | User ID/Principal name | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` |
**group_id** | optional | Group ID | string | `msgoffice365 group id` |
**filter** | optional | OData query to filter/search for specific results | string | |
**limit** | optional | Maximum number of events to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` | |
action_result.parameter.group_id | string | `msgoffice365 group id` | |
action_result.parameter.filter | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.bodyPreview | string | | |
action_result.data.\*.start | string | | |
action_result.data.\*.end | string | | |
action_result.data.\*.location | string | | |
action_result.data.\*.organizer | string | | |
action_result.data.\*.attendees | string | | |
action_result.data.\*.isAllDay | boolean | | True False |
action_result.data.\*.isCancelled | boolean | | True False |
action_result.data.\*.webLink | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list folders'

Get the mail folder hierarchy

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID/Principal name | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` |
**folder_id** | optional | Parent mail folder id or well-known name | string | `msgoffice365 folder id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` | |
action_result.parameter.folder_id | string | `msgoffice365 folder id` | |
action_result.data.\*.id | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.parentFolderId | string | | |
action_result.data.\*.childFolderCount | numeric | | |
action_result.data.\*.unreadItemCount | numeric | | |
action_result.data.\*.totalItemCount | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list group members'

Get group members

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_id** | required | Group ID | string | `msgoffice365 group id` |
**limit** | optional | Maximum number of members to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.group_id | string | `msgoffice365 group id` | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.mail | string | | |
action_result.data.\*.userPrincipalName | string | | |
action_result.data.\*.userType | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list groups'

List all the groups in an organization, including but not limited to Office 365 groups

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | Search for specific results | string | |
**limit** | optional | Maximum number of groups to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.filter | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.mail | string | | |
action_result.data.\*.mailEnabled | boolean | | True False |
action_result.data.\*.mailNickname | string | | |
action_result.data.\*.groupTypes | string | | |
action_result.data.\*.createdDateTime | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list rules'

Get all the messageRule objects defined for the user's inbox

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID/Principal name | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` | |
action_result.data.\*.id | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.sequence | numeric | | |
action_result.data.\*.isEnabled | boolean | | True False |
action_result.data.\*.isReadOnly | boolean | | True False |
action_result.data.\*.hasError | boolean | | True False |
action_result.data.\*.conditions | string | | |
action_result.data.\*.actions | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list users'

Retrieve a list of users

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | Search for specific results | string | |
**limit** | optional | Maximum number of users to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.filter | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.id | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.givenName | string | | |
action_result.data.\*.surname | string | | |
action_result.data.\*.userPrincipalName | string | | |
action_result.data.\*.mail | string | | |
action_result.data.\*.jobTitle | string | | |
action_result.data.\*.mobilePhone | string | | |
action_result.data.\*.officeLocation | string | | |
action_result.data.\*.businessPhones | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'move email'

Move an email to a folder

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to move | string | `msgoffice365 message id` |
**email_address** | required | User's email (mailbox to move from) | string | `email` |
**folder** | required | Destination folder name/path or ID | string | `msgoffice365 folder id` |
**get_folder_id** | optional | Retrieve folder ID from folder name/path | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `msgoffice365 message id` | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.folder | string | `msgoffice365 folder id` | |
action_result.parameter.get_folder_id | boolean | | |
action_result.data.\*.id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.parentFolderId | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'oof check'

Get user's out of office status

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID/Principal name | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` | |
action_result.data.\*.status | string | | |
action_result.data.\*.externalAudience | string | | |
action_result.data.\*.externalReplyMessage | string | | |
action_result.data.\*.internalReplyMessage | string | | |
action_result.data.\*.scheduledStartDateTime | string | | |
action_result.data.\*.scheduledEndDateTime | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'report message'

Add the sender email into the report

Type: **contain** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | Message ID to pick the sender of | string | `msgoffice365 message id` |
**user_id** | required | User ID to base the action of | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` |
**is_message_move_requested** | optional | Indicates whether the message should be moved out of current folder | boolean | |
**report_action** | required | Indicates the type of action to be reported on the message | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.message_id | string | `msgoffice365 message id` | |
action_result.parameter.user_id | string | `msgoffice365 user id` `msgoffice365 user principal name` `email` | |
action_result.parameter.is_message_move_requested | boolean | | |
action_result.parameter.report_action | string | | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'resolve name'

Resolve a name to email addresses

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** | required | User's email address (mailbox) | string | `email` |
**name** | required | Name or email to resolve | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.name | string | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.emailAddress | string | | |
action_result.data.\*.userPrincipalName | string | | |
action_result.data.\*.id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

Search emails in a mailbox

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** | required | User's email address (mailbox) | string | `email` |
**folder** | optional | Folder name/path or ID | string | |
**get_folder_id** | optional | Retrieve folder ID from folder name/path | boolean | |
**subject** | optional | Substring to search in subject | string | |
**sender** | optional | Sender email to search | string | |
**body** | optional | Substring to search in body | string | |
**internet_message_id** | optional | Internet Message ID to search | string | |
**limit** | optional | Maximum number of emails to return | numeric | |
**search_well_known_folders** | optional | Search in well-known folders | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.folder | string | | |
action_result.parameter.get_folder_id | boolean | | |
action_result.parameter.subject | string | | |
action_result.parameter.sender | string | | |
action_result.parameter.body | string | | |
action_result.parameter.internet_message_id | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.search_well_known_folders | boolean | | |
action_result.data.\*.id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.sender | string | | |
action_result.data.\*.receivedDateTime | string | | |
action_result.data.\*.bodyPreview | string | | |
action_result.data.\*.hasAttachments | boolean | | True False |
action_result.data.\*.parentFolderId | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'send email'

Send an email

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**from_email** | required | From email address | string | `email` |
**to** | required | To email addresses (comma-separated) | string | `email` |
**cc** | optional | CC email addresses (comma-separated) | string | |
**bcc** | optional | BCC email addresses (comma-separated) | string | |
**subject** | required | Email subject | string | |
**body** | required | Email body | string | |
**body_is_html** | optional | Is body HTML | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.from_email | string | `email` | |
action_result.parameter.to | string | `email` | |
action_result.parameter.cc | string | | |
action_result.parameter.bcc | string | | |
action_result.parameter.subject | string | | |
action_result.parameter.body | string | | |
action_result.parameter.body_is_html | boolean | | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unblock sender'

Remove a sender from the blocked senders list

Type: **correct** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** | required | User's email address (mailbox) | string | `email` |
**sender** | required | Email address of sender to unblock | string | `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.sender | string | `email` | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update email'

Update properties of an email

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Message ID to update | string | `msgoffice365 message id` |
**email_address** | required | User's email address (mailbox) | string | `email` |
**category** | optional | Category to add to the email | string | |
**is_read** | optional | Mark email as read | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `msgoffice365 message id` | |
action_result.parameter.email_address | string | `email` | |
action_result.parameter.category | string | | |
action_result.parameter.is_read | boolean | | |
action_result.data.\*.id | string | | |
action_result.data.\*.subject | string | | |
action_result.data.\*.isRead | boolean | | True False |
action_result.data.\*.categories | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
