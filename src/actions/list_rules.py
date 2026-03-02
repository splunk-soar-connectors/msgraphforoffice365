# Copyright (c) 2017-2026 Splunk Inc.

import json
from typing import TYPE_CHECKING

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params


if TYPE_CHECKING:
    from ..app import Asset
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


def render_list_rules(output: list[RuleOutput]) -> dict:
    rules = []
    for item in output:
        actions_data = None
        if item.actions:
            try:
                actions_data = (
                    json.loads(item.actions)
                    if isinstance(item.actions, str)
                    else item.actions
                )
            except (json.JSONDecodeError, ValueError):
                actions_data = item.actions

        delete_enabled = None
        if isinstance(actions_data, dict):
            delete_enabled = actions_data.get("delete")

        rules.append(
            {
                "id": item.id,
                "display_name": item.displayName,
                "delete_enabled": delete_enabled,
                "actions": actions_data,
            }
        )

    results = [
        {
            "data": bool(rules),
            "rules": rules,
        }
    ]
    return {"results": results}


def list_rules(
    params: ListRulesParams, soar: SOARClient, asset: "Asset"
) -> list[RuleOutput]:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.user_id}/mailFolders/inbox/messageRules"
    resp = helper.make_rest_call_helper(endpoint)
    rules = resp.get("value", [])

    rules = [serialize_complex_fields(r, ["conditions", "actions"]) for r in rules]
    soar.set_message(f"Successfully retrieved {len(rules)} rules")
    return [RuleOutput(**r) for r in rules]
