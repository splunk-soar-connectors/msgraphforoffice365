# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class ListFoldersParams(Params):
    user_id: str = Param(
        description="User ID/Principal name",
        required=True,
        primary=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
    )
    folder_id: str = Param(
        description="Parent mail folder id or well-known name",
        required=False,
        default="",
        cef_types=["msgoffice365 folder id"],
    )


class FolderOutput(ActionOutput):
    id: str | None = None
    displayName: str | None = None
    parentFolderId: str | None = None
    childFolderCount: int | None = None
    unreadItemCount: int | None = None
    totalItemCount: int | None = None


class ListFoldersSummary(ActionOutput):
    total_folders_returned: int = 0


@app.action(description="Get the mail folder hierarchy", action_type="investigate")
def list_folders(
    params: ListFoldersParams, soar: SOARClient, asset: Asset
) -> list[FolderOutput]:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    if params.folder_id:
        endpoint = (
            f"/users/{params.user_id}/mailFolders/{params.folder_id}/childFolders"
        )
    else:
        endpoint = f"/users/{params.user_id}/mailFolders"

    folders = []
    while True:
        resp = helper.make_rest_call_helper(endpoint)
        folders.extend(resp.get("value", []))

        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break
        resp = helper.make_rest_call_helper(endpoint, nextLink=next_link)

    soar.set_message(f"Successfully retrieved {len(folders)} folders")
    soar.set_summary(ListFoldersSummary(total_folders_returned=len(folders)))
    return [FolderOutput(**f) for f in folders]
