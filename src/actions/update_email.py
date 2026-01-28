# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class UpdateEmailParams(Params):
    id: str = Param(
        description="Message ID to update",
        required=True,
        primary=True,
        cef_types=["msgoffice365 message id"],
    )
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    category: str = Param(
        description="Category to add to the email",
        required=False,
        default="",
    )
    is_read: bool = Param(
        description="Mark email as read",
        required=False,
        default=None,
    )


class UpdateEmailOutput(ActionOutput):
    id: str | None = None
    subject: str | None = None
    isRead: bool | None = None
    categories: str | None = None


@app.action(description="Update properties of an email", action_type="generic")
def update_email(
    params: UpdateEmailParams, soar: SOARClient, asset: Asset
) -> UpdateEmailOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.email_address}/messages/{params.id}"

    body = {}
    if params.category:
        body["categories"] = [params.category]
    if params.is_read is not None:
        body["isRead"] = params.is_read

    if not body:
        raise ValueError(
            "At least one update parameter (category or is_read) must be provided"
        )

    resp = helper.make_rest_call_helper(endpoint, method="patch", data=json.dumps(body))

    soar.set_message("Successfully updated email")
    return UpdateEmailOutput(**resp)
