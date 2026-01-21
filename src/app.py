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

import base64
import hashlib
import re
from collections.abc import Iterator
from html import unescape

from bs4 import BeautifulSoup
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.extras.email.processor import (
    HASH_REGEX,
    IP_REGEX,
    URI_REGEX,
)
from soar_sdk.extras.email.utils import clean_url, is_ip
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.params import OnPollParams

from .consts import (
    MSGOFFICE365_CONTAINER_DESCRIPTION,
    MSGOFFICE365_DEFAULT_FOLDER,
    MSGOFFICE365_ORDERBY_RECEIVED_DESC,
    MSGOFFICE365_PER_PAGE_COUNT,
    MSGOFFICE365_SELECT_PARAMETER_LIST,
)
from .helper import MsGraphHelper


logger = getLogger()

APP_ID = "0a0a4087-10e8-4c96-9872-b740ff26d8bb"


def _extract_urls_domains(
    body: str, extract_urls: bool, extract_domains: bool
) -> tuple[set[str], set[str]]:
    """Extract URLs and domains from email body using SDK utilities."""
    urls: set[str] = set()
    domains: set[str] = set()

    if not extract_urls and not extract_domains:
        return urls, domains

    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception as e:
        logger.debug(f"Error parsing HTML: {e}")
        return urls, domains

    uris = []
    for link in soup.find_all(href=True):
        uris.append(clean_url(link.get_text()))
        if not link["href"].startswith("mailto:"):
            uris.append(link["href"])

    for src in soup.find_all(src=True):
        uris.append(clean_url(src.get_text()))
        uris.append(src["src"])

    body_unescaped = unescape(body)
    regex_uris = re.findall(URI_REGEX, body_unescaped)
    uris.extend(clean_url(x) for x in regex_uris)

    for uri in uris:
        if extract_urls and uri.startswith(("http://", "https://")):
            urls.add(uri)
        if extract_domains:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(uri)
                if parsed.netloc:
                    domains.add(parsed.netloc.split(":")[0])
            except Exception:
                pass

    return urls, domains


def _extract_ips(body: str) -> set[str]:
    """Extract IP addresses from email body using SDK utilities."""
    ips: set[str] = set()
    for match in re.finditer(IP_REGEX, body):
        ip_candidate = match.group(0).strip()
        if is_ip(ip_candidate):
            ips.add(ip_candidate)
    return ips


def _extract_hashes(body: str) -> set[str]:
    """Extract hashes from email body using SDK utilities."""
    return set(re.findall(HASH_REGEX, body))


class Asset(BaseAsset):
    # Connectivity fields
    tenant: str = AssetField(
        required=True,
        description="Tenant ID (e.g. 1e309abf-db6c-XXXX-a1d2-XXXXXXXXXXXX)",
        category=FieldCategory.CONNECTIVITY,
    )
    client_id: str = AssetField(
        required=True,
        description="Application ID",
        category=FieldCategory.CONNECTIVITY,
    )
    auth_type: str = AssetField(
        required=True,
        description="Authentication type to use for connectivity",
        default="Automatic",
        value_list=["Automatic", "OAuth", "Certificate Based Authentication(CBA)"],
        category=FieldCategory.CONNECTIVITY,
    )
    client_secret: str = AssetField(
        required=False,
        description="Application Secret (required for OAuth)",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    certificate_thumbprint: str = AssetField(
        required=False,
        description="Certificate Thumbprint (required for CBA)",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    certificate_private_key: str = AssetField(
        required=False,
        description="Certificate Private Key (.PEM)",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    admin_access: bool = AssetField(
        required=False,
        description="Admin Access Required",
        default=True,
        category=FieldCategory.CONNECTIVITY,
    )
    admin_consent: bool = AssetField(
        required=False,
        description="Admin Consent Already Provided (Required checked for CBA)",
        default=False,
        category=FieldCategory.CONNECTIVITY,
    )
    scope: str = AssetField(
        required=False,
        description="Access Scope (for use with OAuth non-admin access; space-separated)",
        default="https://graph.microsoft.com/Calendars.Read https://graph.microsoft.com/User.Read",
        category=FieldCategory.CONNECTIVITY,
    )
    retry_count: int = AssetField(
        required=False,
        description="Maximum attempts to retry the API call (Default: 3)",
        default=3,
        category=FieldCategory.CONNECTIVITY,
    )
    retry_wait_time: int = AssetField(
        required=False,
        description="Delay in seconds between retries (Default: 60)",
        default=60,
        category=FieldCategory.CONNECTIVITY,
    )

    # Ingestion fields
    email_address: str = AssetField(
        required=False,
        description="Email Address of the User (On Poll)",
        category=FieldCategory.INGEST,
    )
    folder: str = AssetField(
        required=False,
        description="Mailbox folder name/folder path or the internal office365 folder ID to ingest (On Poll)",
        category=FieldCategory.INGEST,
    )
    get_folder_id: bool = AssetField(
        required=False,
        description="Retrieve the folder ID for the provided folder name/folder path automatically",
        default=True,
        category=FieldCategory.INGEST,
    )
    first_run_max_emails: int = AssetField(
        required=False,
        description="Maximum Containers for scheduled polling first time",
        default=1000,
        category=FieldCategory.INGEST,
    )
    max_containers: int = AssetField(
        required=False,
        description="Maximum Containers for scheduled polling",
        default=100,
        category=FieldCategory.INGEST,
    )
    extract_attachments: bool = AssetField(
        required=False,
        description="Extract Attachments",
        default=False,
        category=FieldCategory.INGEST,
    )
    extract_urls: bool = AssetField(
        required=False,
        description="Extract URLs",
        default=False,
        category=FieldCategory.INGEST,
    )
    extract_ips: bool = AssetField(
        required=False,
        description="Extract IPs",
        default=False,
        category=FieldCategory.INGEST,
    )
    extract_domains: bool = AssetField(
        required=False,
        description="Extract Domain Names",
        default=False,
        category=FieldCategory.INGEST,
    )
    extract_hashes: bool = AssetField(
        required=False,
        description="Extract Hashes",
        default=False,
        category=FieldCategory.INGEST,
    )
    ingest_eml: bool = AssetField(
        required=False,
        description="Ingest EML file for the itemAttachment",
        default=False,
        category=FieldCategory.INGEST,
    )
    ingest_manner: str = AssetField(
        required=False,
        description="How to Ingest",
        default="oldest first",
        value_list=["oldest first", "latest first"],
        category=FieldCategory.INGEST,
    )
    extract_eml: bool = AssetField(
        required=False,
        description="Extract root (primary) email as Vault",
        default=False,
        category=FieldCategory.INGEST,
    )


app = App(
    name="MS Graph for Office 365",
    app_type="email",
    logo="logo_microsoftoffice365.svg",
    logo_dark="logo_microsoftoffice365_dark.svg",
    product_vendor="Microsoft",
    product_name="Office 365 (MS Graph)",
    publisher="Splunk",
    appid=APP_ID,
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    params = {"$top": "1"}
    if asset.admin_access or helper._auth_type == "cba":
        logger.info("Getting info about all users to verify token")
        helper.make_rest_call_helper("/users", params=params)
    else:
        logger.info("Getting info about a single user to verify token")
        helper.make_rest_call_helper("/me", params=params)

    soar.set_message("Test Connectivity Passed")
    logger.info("Test Connectivity Passed")


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container | Artifact]:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    state = getattr(asset, "ingest_state", None) or {}
    email_address = asset.email_address
    if not email_address:
        raise ValueError("Email address is required for polling")

    folder = asset.folder or MSGOFFICE365_DEFAULT_FOLDER
    folder_id = folder
    if asset.get_folder_id:
        resolved_id = helper.get_folder_id(folder, email_address)
        if resolved_id:
            folder_id = resolved_id

    is_poll_now = params.container_count is not None
    if is_poll_now:
        max_emails = params.container_count if params.container_count > 0 else 100
        last_time = None
    else:
        is_first_run = state.get("first_run", True)
        max_emails = (
            asset.first_run_max_emails if is_first_run else asset.max_containers
        )
        last_time = state.get("last_time")

    endpoint = f"/users/{email_address}/mailFolders/{folder_id}/messages"
    select_fields = ",".join(MSGOFFICE365_SELECT_PARAMETER_LIST)
    api_params = {
        "$select": select_fields,
        "$top": str(min(max_emails, MSGOFFICE365_PER_PAGE_COUNT)),
        "$orderby": MSGOFFICE365_ORDERBY_RECEIVED_DESC
        if asset.ingest_manner == "latest first"
        else "receivedDateTime asc",
    }

    if last_time and not is_poll_now:
        api_params["$filter"] = f"receivedDateTime gt {last_time}"

    emails_processed = 0
    latest_time = last_time

    while emails_processed < max_emails:
        resp = helper.make_rest_call_helper(endpoint, params=api_params)
        emails = resp.get("value", [])

        if not emails:
            break

        for email_data in emails:
            if emails_processed >= max_emails:
                break

            email_time = email_data.get("receivedDateTime")
            if email_time and (not latest_time or email_time > latest_time):
                latest_time = email_time

            email_id = email_data.get("id")
            container = Container(
                name=email_data.get("subject") or email_id,
                source_data_identifier=email_id,
                description=MSGOFFICE365_CONTAINER_DESCRIPTION.format(
                    last_modified_time=email_data.get("lastModifiedDateTime")
                ),
            )
            yield container

            artifact = Artifact(
                name="Email Artifact",
                label="email",
                cef={
                    "messageId": email_id,
                    "subject": email_data.get("subject"),
                    "fromEmail": email_data.get("from", {})
                    .get("emailAddress", {})
                    .get("address"),
                    "receivedDateTime": email_data.get("receivedDateTime"),
                    "bodyPreview": email_data.get("bodyPreview"),
                },
                cef_types={
                    "messageId": ["msgoffice365 message id"],
                    "fromEmail": ["email"],
                },
            )
            yield artifact

            body = email_data.get("body", {}).get("content", "") or email_data.get(
                "bodyPreview", ""
            )

            if asset.extract_urls or asset.extract_domains:
                urls, domains = _extract_urls_domains(
                    body, asset.extract_urls, asset.extract_domains
                )
                for url in urls:
                    yield Artifact(
                        name="URL Artifact",
                        label="url",
                        cef={"requestURL": url},
                        cef_types={"requestURL": ["url"]},
                    )
                for domain in domains:
                    yield Artifact(
                        name="Domain Artifact",
                        label="domain",
                        cef={"destinationDnsDomain": domain},
                        cef_types={"destinationDnsDomain": ["domain"]},
                    )

            if asset.extract_ips:
                ips = _extract_ips(body)
                for ip in ips:
                    yield Artifact(
                        name="IP Artifact",
                        label="ip",
                        cef={"destinationAddress": ip},
                        cef_types={"destinationAddress": ["ip"]},
                    )

            if asset.extract_hashes:
                hashes = _extract_hashes(body)
                for file_hash in hashes:
                    yield Artifact(
                        name="Hash Artifact",
                        label="hash",
                        cef={"fileHash": file_hash},
                        cef_types={"fileHash": ["hash"]},
                    )

            # extract_eml: Save the root email as EML file to vault
            if asset.extract_eml:
                try:
                    eml_content = helper.make_rest_call_helper(
                        f"/users/{email_address}/messages/{email_id}/$value",
                        download=True,
                    )
                    if eml_content:
                        if isinstance(eml_content, str):
                            eml_content = eml_content.encode("utf-8")
                        file_hash = hashlib.sha256(eml_content).hexdigest()
                        subject = (
                            email_data.get("subject") or f"email_message_{email_id}"
                        )
                        file_name = f"{subject}.eml"
                        vault_info = soar.vault.add(
                            file_content=eml_content,
                            file_name=file_name,
                        )
                        yield Artifact(
                            name="Vault Artifact",
                            label="email attachment",
                            cef={
                                "vaultId": vault_info.vault_id
                                if hasattr(vault_info, "vault_id")
                                else str(vault_info),
                                "fileName": file_name,
                                "fileHashSha256": file_hash,
                            },
                            cef_types={
                                "vaultId": ["vault id"],
                                "fileName": ["file name"],
                                "fileHashSha256": ["hash", "sha256"],
                            },
                        )
                except Exception as e:
                    logger.warning(f"Failed to extract root email as EML: {e}")

            if asset.extract_attachments and email_data.get("hasAttachments"):
                try:
                    attachments_resp = helper.make_rest_call_helper(
                        f"/users/{email_address}/messages/{email_id}/attachments"
                    )
                    for att in attachments_resp.get("value", []):
                        att_type = att.get("@odata.type")

                        # Handle regular file attachments
                        if att_type == "#microsoft.graph.fileAttachment":
                            content_bytes = att.get("contentBytes")
                            if content_bytes:
                                try:
                                    file_content = base64.b64decode(content_bytes)
                                    file_hash = hashlib.sha256(file_content).hexdigest()
                                    vault_info = soar.vault.add(
                                        file_content=file_content,
                                        file_name=att.get("name", "attachment"),
                                    )
                                    yield Artifact(
                                        name="Vault Artifact",
                                        label="attachment",
                                        cef={
                                            "vaultId": vault_info.vault_id
                                            if hasattr(vault_info, "vault_id")
                                            else str(vault_info),
                                            "fileName": att.get("name"),
                                            "fileSize": att.get("size"),
                                            "fileHashSha256": file_hash,
                                        },
                                        cef_types={
                                            "vaultId": ["vault id"],
                                            "fileName": ["file name"],
                                            "fileHashSha256": ["hash", "sha256"],
                                        },
                                    )
                                except Exception as e:
                                    logger.warning(
                                        f"Failed to save attachment to vault: {e}"
                                    )

                        # Handle itemAttachment (embedded emails) - ingest_eml feature
                        elif (
                            att_type == "#microsoft.graph.itemAttachment"
                            and asset.ingest_eml
                        ):
                            att_id = att.get("id")
                            try:
                                eml_content = helper.make_rest_call_helper(
                                    f"/users/{email_address}/messages/{email_id}/attachments/{att_id}/$value",
                                    download=True,
                                )
                                if eml_content:
                                    if isinstance(eml_content, str):
                                        eml_content = eml_content.encode("utf-8")
                                    file_hash = hashlib.sha256(eml_content).hexdigest()
                                    att_name = att.get("name", "embedded_email")
                                    file_name = f"{att_name}.eml"
                                    vault_info = soar.vault.add(
                                        file_content=eml_content,
                                        file_name=file_name,
                                    )
                                    yield Artifact(
                                        name="Vault Artifact",
                                        label="attachment",
                                        cef={
                                            "vaultId": vault_info.vault_id
                                            if hasattr(vault_info, "vault_id")
                                            else str(vault_info),
                                            "fileName": file_name,
                                            "fileSize": att.get("size"),
                                            "lastModified": att.get(
                                                "lastModifiedDateTime"
                                            ),
                                            "mimeType": att.get("contentType"),
                                            "fileHashSha256": file_hash,
                                        },
                                        cef_types={
                                            "vaultId": ["vault id"],
                                            "fileName": ["file name"],
                                            "fileHashSha256": ["hash", "sha256"],
                                        },
                                    )
                            except Exception as e:
                                logger.warning(
                                    f"Failed to save item attachment to vault: {e}"
                                )

                except Exception as e:
                    logger.warning(
                        f"Failed to fetch attachments for email {email_id}: {e}"
                    )

            emails_processed += 1

        next_link = resp.get("@odata.nextLink")
        if not next_link or emails_processed >= max_emails:
            break
        api_params = None
        resp = helper.make_rest_call_helper(endpoint, nextLink=next_link)

    if not is_poll_now and latest_time:
        state["last_time"] = latest_time
        state["first_run"] = False


# Import action modules to register them with the app
from .actions import (  # noqa: F401
    block_sender,
    copy_email,
    create_folder,
    delete_email,
    delete_event,
    generate_token,
    get_email,
    get_email_properties,
    get_folder_id,
    get_mailbox_messages,
    get_rule,
    list_events,
    list_folders,
    list_group_members,
    list_groups,
    list_rules,
    list_users,
    move_email,
    oof_check,
    report_message,
    resolve_name,
    run_query,
    send_email,
    unblock_sender,
    update_email,
)


if __name__ == "__main__":
    app.cli()
