# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class SendEmailParams(Params):
    from_email: str = Param(
        description="From email address",
        required=True,
        cef_types=["email"],
    )
    to: str = Param(
        description="To email addresses (comma-separated)",
        required=True,
        cef_types=["email"],
    )
    cc: str = Param(
        description="CC email addresses (comma-separated)",
        required=False,
        default="",
    )
    bcc: str = Param(
        description="BCC email addresses (comma-separated)",
        required=False,
        default="",
    )
    subject: str = Param(
        description="Email subject",
        required=True,
    )
    body: str = Param(
        description="Email body",
        required=True,
    )
    body_is_html: bool = Param(
        description="Is body HTML",
        required=False,
        default=False,
    )


class SendEmailOutput(ActionOutput):
    message: str | None = None


def _parse_recipients(email_str: str) -> list:
    if not email_str:
        return []
    emails = [e.strip() for e in email_str.split(",") if e.strip()]
    return [{"emailAddress": {"address": e}} for e in emails]


@app.action(description="Send an email", action_type="generic")
def send_email(
    params: SendEmailParams, soar: SOARClient, asset: Asset
) -> SendEmailOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    message = {
        "subject": params.subject,
        "body": {
            "contentType": "HTML" if params.body_is_html else "Text",
            "content": params.body,
        },
        "toRecipients": _parse_recipients(params.to),
    }

    if params.cc:
        message["ccRecipients"] = _parse_recipients(params.cc)
    if params.bcc:
        message["bccRecipients"] = _parse_recipients(params.bcc)

    endpoint = f"/users/{params.from_email}/sendMail"
    body = {"message": message, "saveToSentItems": True}
    helper.make_rest_call_helper(endpoint, method="post", data=json.dumps(body))

    soar.set_message("Email sent successfully")
    return SendEmailOutput(message="Email sent successfully")
