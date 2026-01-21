# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class UnblockSenderParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    sender: str = Param(
        description="Email address of sender to unblock",
        required=True,
        cef_types=["email"],
    )


class UnblockSenderOutput(ActionOutput):
    message: str | None = None


@app.action(
    description="Remove a sender from the blocked senders list", action_type="correct"
)
def unblock_sender(
    params: UnblockSenderParams, soar: SOARClient, asset: Asset
) -> UnblockSenderOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.email_address}/mailFolders/inbox/messageRules"
    resp = helper.make_rest_call_helper(endpoint)

    rules = resp.get("value", [])
    rule_id = None
    for rule in rules:
        display_name = rule.get("displayName", "")
        if f"Block sender: {params.sender}" in display_name:
            rule_id = rule.get("id")
            break

    if not rule_id:
        raise ValueError(f"No blocking rule found for sender: {params.sender}")

    delete_endpoint = (
        f"/users/{params.email_address}/mailFolders/inbox/messageRules/{rule_id}"
    )
    helper.make_rest_call_helper(delete_endpoint, method="delete")

    soar.set_message(f"Successfully unblocked sender: {params.sender}")
    return UnblockSenderOutput(
        message=f"Successfully unblocked sender: {params.sender}"
    )
