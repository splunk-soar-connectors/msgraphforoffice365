# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class DeleteEmailParams(Params):
    id: str = Param(
        description="Message ID to delete",
        required=True,
        primary=True,
        cef_types=["msgoffice365 message id"],
    )
    email_address: str = Param(
        description="User's email (mailbox to delete from)",
        required=True,
        cef_types=["email"],
    )


class DeleteEmailOutput(ActionOutput):
    message: str | None = None


@app.action(description="Delete an email", action_type="generic")
def delete_email(
    params: DeleteEmailParams, soar: SOARClient, asset: Asset
) -> DeleteEmailOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.email_address}/messages/{params.id}"
    helper.make_rest_call_helper(endpoint, method="delete")

    soar.set_message("Email deleted successfully")
    return DeleteEmailOutput(message="Email deleted successfully")
