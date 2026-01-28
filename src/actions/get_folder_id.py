# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class GetFolderIdParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        primary=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
    )
    folder: str = Param(
        description="Folder name or path (e.g. 'Inbox' or 'Inbox/Subfolder')",
        required=True,
    )


class GetFolderIdOutput(ActionOutput):
    folder_id: str | None = None
    folder_name: str | None = None
    display_name: str | None = None
    parent_folder_id: str | None = None


@app.action(description="Get the ID of a mail folder", action_type="investigate")
def get_folder_id(
    params: GetFolderIdParams, soar: SOARClient, asset: Asset
) -> GetFolderIdOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    folder_id = helper.get_folder_id(params.folder, params.email_address)
    if not folder_id:
        raise ValueError(f"Could not find folder: {params.folder}")

    endpoint = f"/users/{params.email_address}/mailFolders/{folder_id}"
    resp = helper.make_rest_call_helper(endpoint)

    soar.set_message(f"Successfully retrieved folder ID: {folder_id}")
    return GetFolderIdOutput(
        folder_id=resp.get("id"),
        folder_name=params.folder,
        display_name=resp.get("displayName"),
        parent_folder_id=resp.get("parentFolderId"),
    )
