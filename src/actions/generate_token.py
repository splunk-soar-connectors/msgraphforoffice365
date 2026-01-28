# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class GenerateTokenParams(Params):
    pass


class GenerateTokenOutput(ActionOutput):
    message: str | None = None


@app.action(
    description="Generates a new access token",
    action_type="generic",
)
def generate_token(
    params: GenerateTokenParams, soar: SOARClient, asset: Asset
) -> GenerateTokenOutput:
    helper = MsGraphHelper(soar, asset)
    helper._access_token = None
    helper.get_token()

    soar.set_message("Token generated successfully")
    return GenerateTokenOutput(message="Token generated successfully")
