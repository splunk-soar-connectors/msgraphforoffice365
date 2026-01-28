# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class ListGroupsParams(Params):
    filter: str = Param(
        description="Search for specific results", required=False, default=""
    )
    limit: int = Param(
        description="Maximum number of groups to return", required=False, default=0
    )


class GroupOutput(ActionOutput):
    id: str | None = None
    displayName: str | None = None
    description: str | None = None
    mail: str | None = None
    mailEnabled: bool | None = None
    mailNickname: str | None = None
    groupTypes: list[str] | None = None
    createdDateTime: str | None = None


@app.action(
    description="List all the groups in an organization, including but not limited to Office 365 groups",
    action_type="investigate",
)
def list_groups(
    params: ListGroupsParams, soar: SOARClient, asset: Asset
) -> list[GroupOutput]:
    if params.limit is not None and params.limit < 0:
        raise ValueError("'limit' action parameter must be a non-negative integer")

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = "/groups"
    api_params = {}
    if params.filter:
        api_params["$filter"] = params.filter
    if params.limit and params.limit > 0:
        api_params["$top"] = str(params.limit)

    groups = []
    while True:
        resp = helper.make_rest_call_helper(
            endpoint, params=api_params if api_params else None
        )
        groups.extend(resp.get("value", []))

        if params.limit and len(groups) >= params.limit:
            groups = groups[: params.limit]
            break

        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break
        resp = helper.make_rest_call_helper(endpoint, nextLink=next_link)
        api_params = None

    soar.set_message(f"Successfully retrieved {len(groups)} groups")
    return [GroupOutput(**g) for g in groups]
