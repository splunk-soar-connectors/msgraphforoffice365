# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class ListGroupMembersParams(Params):
    group_id: str = Param(
        description="Group ID",
        required=True,
        primary=True,
        cef_types=["msgoffice365 group id"],
    )
    limit: int = Param(
        description="Maximum number of members to return", required=False, default=0
    )


class GroupMemberOutput(ActionOutput):
    id: str | None = None
    displayName: str | None = None
    mail: str | None = None
    userPrincipalName: str | None = None
    userType: str | None = None


@app.action(description="Get group members", action_type="investigate")
def list_group_members(
    params: ListGroupMembersParams, soar: SOARClient, asset: Asset
) -> list[GroupMemberOutput]:
    if params.limit is not None and params.limit < 0:
        raise ValueError("'limit' action parameter must be a non-negative integer")

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/groups/{params.group_id}/members"
    api_params = {}
    if params.limit and params.limit > 0:
        api_params["$top"] = str(params.limit)

    members = []
    while True:
        resp = helper.make_rest_call_helper(
            endpoint, params=api_params if api_params else None
        )
        members.extend(resp.get("value", []))

        if params.limit and len(members) >= params.limit:
            members = members[: params.limit]
            break

        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break
        resp = helper.make_rest_call_helper(endpoint, nextLink=next_link)
        api_params = None

    soar.set_message(f"Successfully retrieved {len(members)} members")
    return [GroupMemberOutput(**m) for m in members]
