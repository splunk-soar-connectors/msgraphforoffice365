# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class BlockSenderParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    sender: str = Param(
        description="Email address of sender to block",
        required=True,
        cef_types=["email"],
    )


class BlockSenderOutput(ActionOutput):
    message: str | None = None


@app.action(
    description="Add a sender to the blocked senders list", action_type="contain"
)
def block_sender(
    params: BlockSenderParams, soar: SOARClient, asset: Asset
) -> BlockSenderOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.email_address}/mailFolders/junkemail/messageRules"
    body = {
        "displayName": f"Block sender: {params.sender}",
        "sequence": 1,
        "isEnabled": True,
        "conditions": {"senderContains": [params.sender]},
        "actions": {"delete": True, "stopProcessingRules": True},
    }

    helper.make_rest_call_helper(endpoint, method="post", data=json.dumps(body))

    soar.set_message(f"Successfully blocked sender: {params.sender}")
    return BlockSenderOutput(message=f"Successfully blocked sender: {params.sender}")
