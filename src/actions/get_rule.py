# Copyright (c) 2017-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper, serialize_complex_fields


class GetRuleParams(Params):
    user_id: str = Param(
        description="User ID/Principal name",
        required=True,
        primary=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
    )
    rule_id: str = Param(
        description="Inbox rule ID",
        required=True,
        primary=True,
        cef_types=["msgoffice365 rule id"],
    )


class GetRuleOutput(ActionOutput):
    id: str | None = None
    displayName: str | None = None
    sequence: int | None = None
    isEnabled: bool | None = None
    isReadOnly: bool | None = None
    hasError: bool | None = None
    conditions: str | None = None
    actions: str | None = None


@app.action(
    description="Get the properties and relationships of a messageRule object",
    action_type="investigate",
)
def get_rule(params: GetRuleParams, soar: SOARClient, asset: Asset) -> GetRuleOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = (
        f"/users/{params.user_id}/mailFolders/inbox/messageRules/{params.rule_id}"
    )
    resp = helper.make_rest_call_helper(endpoint)

    resp = serialize_complex_fields(resp, ["conditions", "actions"])
    soar.set_message("Successfully retrieved specified inbox rule")
    return GetRuleOutput(**resp)
