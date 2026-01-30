# Copyright (c) 2017-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper, serialize_complex_fields


class ListRulesParams(Params):
    user_id: str = Param(
        description="User ID/Principal name",
        required=True,
        primary=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
    )


class RuleOutput(ActionOutput):
    id: str | None = None
    displayName: str | None = None
    sequence: int | None = None
    isEnabled: bool | None = None
    isReadOnly: bool | None = None
    hasError: bool | None = None
    conditions: str | None = None
    actions: str | None = None


@app.action(
    description="Get all the messageRule objects defined for the user's inbox",
    action_type="investigate",
)
def list_rules(
    params: ListRulesParams, soar: SOARClient, asset: Asset
) -> list[RuleOutput]:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.user_id}/mailFolders/inbox/messageRules"
    resp = helper.make_rest_call_helper(endpoint)
    rules = resp.get("value", [])

    rules = [serialize_complex_fields(r, ["conditions", "actions"]) for r in rules]
    soar.set_message(f"Successfully retrieved {len(rules)} rules")
    return [RuleOutput(**r) for r in rules]
