# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class DeleteEventParams(Params):
    event_id: str = Param(
        description="Event ID to delete",
        required=True,
        primary=True,
        cef_types=["msgoffice365 event id"],
    )
    user_id: str = Param(
        description="User ID/Principal name",
        required=False,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
        default="",
    )
    group_id: str = Param(
        description="Group ID",
        required=False,
        cef_types=["msgoffice365 group id"],
        default="",
    )


class DeleteEventOutput(ActionOutput):
    message: str | None = None


@app.action(description="Delete an event", action_type="generic")
def delete_event(
    params: DeleteEventParams, soar: SOARClient, asset: Asset
) -> DeleteEventOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    if not params.user_id and not params.group_id:
        raise ValueError("Either user_id or group_id must be provided")

    if params.user_id:
        endpoint = f"/users/{params.user_id}/events/{params.event_id}"
    else:
        endpoint = f"/groups/{params.group_id}/events/{params.event_id}"

    helper.make_rest_call_helper(endpoint, method="delete")

    soar.set_message("Event deleted successfully")
    return DeleteEventOutput(message="Event deleted successfully")
