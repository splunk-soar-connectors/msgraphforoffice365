# Copyright (c) 2017-2026 Splunk Inc.

import json
from typing import TYPE_CHECKING

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params


if TYPE_CHECKING:
    from ..app import Asset
from ..helper import MsGraphHelper, serialize_complex_fields


class GetEmailParams(Params):
    id: str = Param(
        description="Message ID to get",
        required=True,
        primary=True,
        cef_types=["msgoffice365 message id"],
    )
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    get_headers: bool = Param(
        description="Get email headers",
        required=False,
        default=True,
    )
    download_attachments: bool = Param(
        description="Download attachments",
        required=False,
        default=False,
    )
    download_email: bool = Param(
        description="Download email as EML file",
        required=False,
        default=False,
    )


class GetEmailOutput(ActionOutput):
    id: str | None = None
    subject: str | None = None
    body: str | None = None
    bodyPreview: str | None = None
    sender: str | None = None
    from_field: str | None = None
    toRecipients: str | None = None
    ccRecipients: str | None = None
    bccRecipients: str | None = None
    receivedDateTime: str | None = None
    sentDateTime: str | None = None
    hasAttachments: bool | None = None
    importance: str | None = None
    isRead: bool | None = None
    internetMessageId: str | None = None
    internetMessageHeaders: str | None = None
    attachments: str | None = None
    event_id: str | None = None


COMPLEX_EMAIL_FIELDS = [
    "body",
    "sender",
    "toRecipients",
    "ccRecipients",
    "bccRecipients",
    "internetMessageHeaders",
    "attachments",
]


def _parse_json_field(val):
    if not val:
        return None
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, ValueError):
            return None
    return val


def _categorize_attachments(attachments_json):
    attachments = _parse_json_field(attachments_json)
    if not attachments:
        return None
    file_att, item_att, ref_att, other_att = [], [], [], []
    for att in attachments:
        att_type = att.get("attachmentType", att.get("@odata.type", ""))
        if att_type == "#microsoft.graph.fileAttachment":
            file_att.append(att)
        elif att_type == "#microsoft.graph.itemAttachment":
            item_att.append(att)
        elif att_type == "#microsoft.graph.referenceAttachment":
            ref_att.append(att)
        else:
            other_att.append(att)
    return {
        "file_attachment": file_att,
        "item_attachment": item_att,
        "reference_attachment": ref_att,
        "other_attachment": other_att,
    }


def _extract_email_address(json_str, path=("emailAddress", "address")):
    data = _parse_json_field(json_str)
    if not data:
        return None
    for key in path:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def _extract_recipient_addresses(json_str):
    data = _parse_json_field(json_str)
    if not data or not isinstance(data, list):
        return []
    return [
        r.get("emailAddress", {}).get("address", "")
        for r in data
        if r.get("emailAddress", {}).get("address")
    ]


def render_get_email(output: list[GetEmailOutput]) -> dict:
    results = []
    for item in output:
        from_addr = _extract_email_address(item.from_field) or _extract_email_address(
            item.sender
        )
        to_addrs = _extract_recipient_addresses(item.toRecipients)
        attachment_data = _categorize_attachments(item.attachments)

        emails = [
            {
                "id": item.id,
                "subject": item.subject,
                "body_preview": item.bodyPreview,
                "from_address": from_addr,
                "to_addresses": to_addrs,
                "has_attachments": item.hasAttachments,
                "internet_message_id": item.internetMessageId,
                "event_id": item.event_id,
            }
        ]

        results.append(
            {
                "data": True,
                "param_id": item.id,
                "param_email_address": None,
                "param_download_attachments": None,
                "param_get_headers": None,
                "emails": emails,
                "has_attachments": item.hasAttachments,
                "attachment_data": attachment_data,
            }
        )
    return {"results": results}


def get_email(
    params: GetEmailParams, soar: SOARClient, asset: "Asset"
) -> GetEmailOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.email_address}/messages/{params.id}"
    resp = helper.make_rest_call_helper(endpoint)

    if params.get_headers:
        header_endpoint = f"{endpoint}?$select=internetMessageHeaders"
        header_resp = helper.make_rest_call_helper(header_endpoint)
        headers = header_resp.get("internetMessageHeaders", [])
        resp["internetMessageHeaders"] = (
            {h["name"]: h["value"] for h in headers} if headers else {}
        )

    if params.download_attachments and resp.get("hasAttachments"):
        attach_endpoint = f"{endpoint}/attachments"
        attach_resp = helper.make_rest_call_helper(attach_endpoint)
        resp["attachments"] = attach_resp.get("value", [])

    resp["from_field"] = resp.pop("from", None)
    resp["event_id"] = (
        resp.get("event", {}).get("id") if isinstance(resp.get("event"), dict) else None
    )

    resp = serialize_complex_fields(resp, [*COMPLEX_EMAIL_FIELDS, "from_field"])
    soar.set_message("Successfully retrieved email")
    return GetEmailOutput(**resp)
