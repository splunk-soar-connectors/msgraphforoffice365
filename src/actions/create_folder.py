# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class CreateFolderParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    folder: str = Param(
        description="Name of the folder to create",
        required=True,
    )
    parent_folder: str = Param(
        description="Parent folder name/path or ID (leave empty for root)",
        required=False,
        default="",
    )
    get_folder_id: bool = Param(
        description="Retrieve parent folder ID from folder name/path",
        required=False,
        default=True,
    )


class CreateFolderOutput(ActionOutput):
    id: str | None = None
    displayName: str | None = None
    parentFolderId: str | None = None
    childFolderCount: int | None = None
    totalItemCount: int | None = None


@app.action(description="Create a new mail folder", action_type="generic")
def create_folder(
    params: CreateFolderParams, soar: SOARClient, asset: Asset
) -> CreateFolderOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    parent_folder_id = None
    if params.parent_folder:
        if params.get_folder_id:
            parent_folder_id = helper.get_folder_id(
                params.parent_folder, params.email_address
            )
        else:
            parent_folder_id = params.parent_folder

    if parent_folder_id:
        endpoint = (
            f"/users/{params.email_address}/mailFolders/{parent_folder_id}/childFolders"
        )
    else:
        endpoint = f"/users/{params.email_address}/mailFolders"

    body = {"displayName": params.folder}
    resp = helper.make_rest_call_helper(endpoint, method="post", data=json.dumps(body))

    soar.set_message(f"Successfully created folder: {params.folder}")
    return CreateFolderOutput(**resp)
