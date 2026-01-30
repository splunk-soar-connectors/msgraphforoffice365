# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class ReportMessageParams(Params):
    message_id: str = Param(
        description="Message ID to pick the sender of",
        required=True,
        cef_types=["msgoffice365 message id"],
    )
    user_id: str = Param(
        description="User ID to base the action of",
        required=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
    )
    is_message_move_requested: bool = Param(
        description="Indicates whether the message should be moved out of current folder",
        required=False,
        default=False,
    )
    report_action: str = Param(
        description="Indicates the type of action to be reported on the message",
        required=True,
        value_list=["junk", "notJunk", "phish", "unknown", "unknownFutureValue"],
    )


class ReportMessageOutput(ActionOutput):
    message: str | None = None


@app.action(
    description="Add the sender email into the report",
    action_type="contain",
)
def report_message(
    params: ReportMessageParams, soar: SOARClient, asset: Asset
) -> ReportMessageOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.user_id}/messages/{params.message_id}/markAsJunk"

    body = {
        "moveToJunk": params.is_message_move_requested
        if params.report_action == "junk"
        else False,
    }

    if params.report_action in ["junk", "phish"]:
        helper.make_rest_call_helper(endpoint, method="post", data=json.dumps(body))
    elif params.report_action == "notJunk":
        body["moveToJunk"] = False
        helper.make_rest_call_helper(endpoint, method="post", data=json.dumps(body))

    soar.set_message(f"Successfully reported message as {params.report_action}")
    return ReportMessageOutput(
        message=f"Successfully reported message as {params.report_action}"
    )
