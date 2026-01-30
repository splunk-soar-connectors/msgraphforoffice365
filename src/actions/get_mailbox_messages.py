# Copyright (c) 2017-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..consts import MSGOFFICE365_PER_PAGE_COUNT, MSGOFFICE365_SELECT_PARAMETER_LIST
from ..helper import MsGraphHelper, serialize_complex_fields


class GetMailboxMessagesParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    folder: str = Param(
        description="Folder name/path or ID",
        required=False,
        default="Inbox",
    )
    get_folder_id: bool = Param(
        description="Retrieve folder ID from folder name/path",
        required=False,
        default=True,
    )
    limit: int = Param(
        description="Maximum number of messages to return",
        required=False,
        default=100,
    )
    offset: int = Param(
        description="Number of messages to skip",
        required=False,
        default=0,
    )


class MessageOutput(ActionOutput):
    id: str | None = None
    subject: str | None = None
    sender: str | None = None
    receivedDateTime: str | None = None
    bodyPreview: str | None = None
    hasAttachments: bool | None = None
    isRead: bool | None = None
    importance: str | None = None


@app.action(description="Get messages from a mailbox folder", action_type="investigate")
def get_mailbox_messages(
    params: GetMailboxMessagesParams, soar: SOARClient, asset: Asset
) -> list[MessageOutput]:
    if params.limit is not None and params.limit <= 0:
        raise ValueError("'limit' action parameter must be a positive integer")

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    folder_id = params.folder
    if params.get_folder_id and params.folder:
        resolved_id = helper.get_folder_id(params.folder, params.email_address)
        if resolved_id:
            folder_id = resolved_id

    endpoint = f"/users/{params.email_address}/mailFolders/{folder_id}/messages"
    select_fields = ",".join(MSGOFFICE365_SELECT_PARAMETER_LIST)
    api_params = {
        "$select": select_fields,
        "$top": str(min(params.limit, MSGOFFICE365_PER_PAGE_COUNT)),
        "$orderby": "receivedDateTime desc",
    }

    if params.offset > 0:
        api_params["$skip"] = str(params.offset)

    messages = []
    next_link = None
    while len(messages) < params.limit:
        resp = helper.make_rest_call_helper(
            endpoint, params=api_params, nextLink=next_link
        )
        messages.extend(resp.get("value", []))

        next_link = resp.get("@odata.nextLink")
        if not next_link or len(messages) >= params.limit:
            break
        api_params = None

    messages = messages[: params.limit]
    messages = [serialize_complex_fields(m, ["sender"]) for m in messages]
    soar.set_message(f"Successfully retrieved {len(messages)} messages")
    return [MessageOutput(**m) for m in messages]
