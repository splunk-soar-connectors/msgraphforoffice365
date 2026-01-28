# Copyright (c) 2017-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
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
    toRecipients: str | None = None
    ccRecipients: str | None = None
    bccRecipients: str | None = None
    receivedDateTime: str | None = None
    sentDateTime: str | None = None
    hasAttachments: bool | None = None
    importance: str | None = None
    isRead: bool | None = None
    internetMessageHeaders: str | None = None
    attachments: str | None = None


COMPLEX_EMAIL_FIELDS = [
    "body",
    "sender",
    "toRecipients",
    "ccRecipients",
    "bccRecipients",
    "internetMessageHeaders",
    "attachments",
]


@app.action(description="Get an email from the server", action_type="investigate")
def get_email(params: GetEmailParams, soar: SOARClient, asset: Asset) -> GetEmailOutput:
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

    resp = serialize_complex_fields(resp, COMPLEX_EMAIL_FIELDS)
    soar.set_message("Successfully retrieved email")
    return GetEmailOutput(**resp)
