# Copyright (c) 2017-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper, serialize_complex_fields


class OofCheckParams(Params):
    user_id: str = Param(
        description="User ID/Principal name",
        required=True,
        primary=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
    )


class OofCheckOutput(ActionOutput):
    status: str | None = None
    externalAudience: str | None = None
    externalReplyMessage: str | None = None
    internalReplyMessage: str | None = None
    scheduledStartDateTime: str | None = None
    scheduledEndDateTime: str | None = None


@app.action(description="Get user's out of office status", action_type="investigate")
def oof_check(params: OofCheckParams, soar: SOARClient, asset: Asset) -> OofCheckOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.user_id}/mailboxSettings/automaticRepliesSetting"
    resp = helper.make_rest_call_helper(endpoint)

    resp = serialize_complex_fields(
        resp, ["scheduledStartDateTime", "scheduledEndDateTime"]
    )
    soar.set_message("Successfully retrieved out of office status")
    return OofCheckOutput(**resp)
