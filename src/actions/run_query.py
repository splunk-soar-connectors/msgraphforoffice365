# Copyright (c) 2017-2026 Splunk Inc.

import json
from typing import TYPE_CHECKING

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params


if TYPE_CHECKING:
    from ..app import Asset
from ..consts import MSGOFFICE365_PER_PAGE_COUNT, MSGOFFICE365_SELECT_PARAMETER_LIST
from ..helper import MsGraphHelper, serialize_complex_fields


class RunQueryParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    folder: str = Param(
        description="Folder name/path or ID",
        required=False,
        default="Inbox",
    )
    get_folder_id: bool = Param(
        description="Retrieve folder ID from folder name/path",
        required=False,
        default=True,
    )
    subject: str = Param(
        description="Substring to search in subject",
        required=False,
        default="",
    )
    sender: str = Param(
        description="Sender email to search",
        required=False,
        default="",
    )
    body: str = Param(
        description="Substring to search in body",
        required=False,
        default="",
    )
    internet_message_id: str = Param(
        description="Internet Message ID to search",
        required=False,
        default="",
    )
    limit: int = Param(
        description="Maximum number of emails to return",
        required=False,
        default=100,
    )
    search_well_known_folders: bool = Param(
        description="Search in well-known folders",
        required=False,
        default=False,
    )


class EmailResult(ActionOutput):
    id: str | None = None
    subject: str | None = None
    sender: str | None = None
    receivedDateTime: str | None = None
    bodyPreview: str | None = None
    hasAttachments: bool | None = None
    internetMessageId: str | None = None
    parentFolderId: str | None = None


class RunQuerySummary(ActionOutput):
    emails_matched: int = 0


def _extract_sender_address(sender_json):
    if not sender_json:
        return None
    try:
        data = json.loads(sender_json) if isinstance(sender_json, str) else sender_json
        return data.get("emailAddress", {}).get("address")
    except (json.JSONDecodeError, AttributeError, ValueError):
        return None


def render_run_query(output: list[EmailResult]) -> dict:
    emails = []
    for item in output:
        emails.append(
            {
                "id": item.id,
                "subject": item.subject,
                "sender_address": _extract_sender_address(item.sender),
                "received_date_time": item.receivedDateTime,
                "body_preview": item.bodyPreview,
                "internet_message_id": item.internetMessageId,
            }
        )

    results = [
        {
            "data": bool(emails),
            "param_email_address": None,
            "param_folder": None,
            "param_get_folder_id": None,
            "param_subject": None,
            "param_body": None,
            "param_sender": None,
            "param_limit": None,
            "param_internet_message_id": None,
            "emails": emails,
        }
    ]
    return {"results": results}


def run_query(
    params: RunQueryParams, soar: SOARClient, asset: "Asset"
) -> list[EmailResult]:
    if params.limit is not None and params.limit <= 0:
        raise ValueError("'limit' action parameter must be a positive integer")

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    folder_id = params.folder
    if params.get_folder_id and params.folder:
        resolved_id = helper.get_folder_id(params.folder, params.email_address)
        if resolved_id:
            folder_id = resolved_id

    if params.search_well_known_folders:
        endpoint = f"/users/{params.email_address}/messages"
    else:
        endpoint = f"/users/{params.email_address}/mailFolders/{folder_id}/messages"

    filters = []
    if params.subject:
        filters.append(f"contains(subject, '{params.subject}')")
    if params.sender:
        filters.append(f"from/emailAddress/address eq '{params.sender}'")
    if params.internet_message_id:
        filters.append(f"internetMessageId eq '{params.internet_message_id}'")

    search = None
    if params.body:
        search = f'"{params.body}"'

    select_fields = ",".join(MSGOFFICE365_SELECT_PARAMETER_LIST)
    api_params = {"$select": select_fields}
    if filters:
        api_params["$filter"] = " and ".join(filters)
    if search:
        api_params["$search"] = search
    if params.limit:
        api_params["$top"] = str(min(params.limit, MSGOFFICE365_PER_PAGE_COUNT))

    emails = []
    next_link = None
    while len(emails) < params.limit:
        resp = helper.make_rest_call_helper(
            endpoint, params=api_params, nextLink=next_link
        )
        emails.extend(resp.get("value", []))

        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break
        api_params = None

    emails = emails[: params.limit]
    emails = [serialize_complex_fields(e, ["sender"]) for e in emails]
    soar.set_message(f"Successfully retrieved {len(emails)} emails")
    soar.set_summary(RunQuerySummary(emails_matched=len(emails)))
    return [EmailResult(**e) for e in emails]
