# Copyright (c) 2017-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper, serialize_complex_fields


class GetEmailPropertiesParams(Params):
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
    get_body: bool = Param(
        description="Get email body",
        required=False,
        default=True,
    )
    get_unique_body: bool = Param(
        description="Get unique body (without previous replies)",
        required=False,
        default=False,
    )
    get_sender: bool = Param(
        description="Get sender information",
        required=False,
        default=True,
    )
    download_attachments: bool = Param(
        description="Download attachments",
        required=False,
        default=False,
    )


class GetEmailPropertiesOutput(ActionOutput):
    id: str | None = None
    subject: str | None = None
    body: str | None = None
    uniqueBody: str | None = None
    bodyPreview: str | None = None
    sender: str | None = None
    toRecipients: str | None = None
    ccRecipients: str | None = None
    receivedDateTime: str | None = None
    hasAttachments: bool | None = None
    internetMessageHeaders: str | None = None
    attachments: str | None = None


COMPLEX_EMAIL_PROPS_FIELDS = [
    "body",
    "uniqueBody",
    "sender",
    "toRecipients",
    "ccRecipients",
    "internetMessageHeaders",
    "attachments",
]


@app.action(description="Get properties of an email", action_type="investigate")
def get_email_properties(
    params: GetEmailPropertiesParams, soar: SOARClient, asset: Asset
) -> GetEmailPropertiesOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    select_fields = [
        "id",
        "subject",
        "bodyPreview",
        "receivedDateTime",
        "hasAttachments",
        "toRecipients",
        "ccRecipients",
    ]
    if params.get_body:
        select_fields.append("body")
    if params.get_unique_body:
        select_fields.append("uniqueBody")
    if params.get_sender:
        select_fields.extend(["sender", "from"])

    endpoint = f"/users/{params.email_address}/messages/{params.id}"
    api_params = {"$select": ",".join(select_fields)}
    resp = helper.make_rest_call_helper(endpoint, params=api_params)

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

    resp = serialize_complex_fields(resp, COMPLEX_EMAIL_PROPS_FIELDS)
    soar.set_message("Successfully retrieved email properties")
    return GetEmailPropertiesOutput(**resp)
