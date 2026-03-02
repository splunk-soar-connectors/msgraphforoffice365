# Copyright (c) 2017-2026 Splunk Inc.

import json
from typing import TYPE_CHECKING

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params


if TYPE_CHECKING:
    from ..app import Asset
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


def _parse_json_field(val):
    if not val:
        return {}
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, ValueError):
            return {}
    return val if isinstance(val, dict) else {}


def _extract_keyed_items(data, keyword):
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if keyword in k.lower()}


def render_get_rule(output: list[GetRuleOutput]) -> dict:
    rules = []
    for item in output:
        actions_data = _parse_json_field(item.actions)
        conditions_data = _parse_json_field(item.conditions)
        rules.append(
            {
                "display_name": item.displayName,
                "action_items": actions_data if isinstance(actions_data, dict) else {},
                "condition_items": conditions_data
                if isinstance(conditions_data, dict)
                else {},
            }
        )

    results = [
        {
            "data": bool(rules),
            "user_id": None,
            "rule_id": None,
            "rules": rules,
        }
    ]
    return {"results": results}


def get_rule(params: GetRuleParams, soar: SOARClient, asset: "Asset") -> GetRuleOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = (
        f"/users/{params.user_id}/mailFolders/inbox/messageRules/{params.rule_id}"
    )
    resp = helper.make_rest_call_helper(endpoint)

    resp = serialize_complex_fields(resp, ["conditions", "actions"])
    soar.set_message("Successfully retrieved specified inbox rule")
    return GetRuleOutput(**resp)
