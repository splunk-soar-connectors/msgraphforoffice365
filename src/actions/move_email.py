# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class MoveEmailParams(Params):
    id: str = Param(
        description="Message ID to move",
        required=True,
        primary=True,
        cef_types=["msgoffice365 message id"],
    )
    email_address: str = Param(
        description="User's email (mailbox to move from)",
        required=True,
        cef_types=["email"],
    )
    folder: str = Param(
        description="Destination folder name/path or ID",
        required=True,
        cef_types=["msgoffice365 folder id"],
    )
    get_folder_id: bool = Param(
        description="Retrieve folder ID from folder name/path",
        required=False,
        default=True,
    )


class MoveEmailOutput(ActionOutput):
    id: str | None = None
    subject: str | None = None
    parentFolderId: str | None = None


@app.action(description="Move an email to a folder", action_type="generic")
def move_email(
    params: MoveEmailParams, soar: SOARClient, asset: Asset
) -> MoveEmailOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    folder_id = params.folder
    if params.get_folder_id:
        resolved_id = helper.get_folder_id(params.folder, params.email_address)
        if resolved_id:
            folder_id = resolved_id
        else:
            raise ValueError(f"Could not resolve folder: {params.folder}")

    endpoint = f"/users/{params.email_address}/messages/{params.id}/move"
    body = {"DestinationId": folder_id}
    resp = helper.make_rest_call_helper(endpoint, method="post", data=json.dumps(body))

    soar.set_message("Successfully moved email")
    return MoveEmailOutput(**resp)
