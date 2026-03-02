# Copyright (c) 2017-2026 Splunk Inc.
from typing import TYPE_CHECKING

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params


if TYPE_CHECKING:
    from ..app import Asset
from ..helper import MsGraphHelper


class ResolveNameParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    name: str = Param(
        description="Name or email to resolve",
        required=True,
    )


class ResolvedContact(ActionOutput):
    displayName: str | None = None
    emailAddress: str | None = None
    userPrincipalName: str | None = None
    id: str | None = None


def render_resolve_name(output: list[ResolvedContact]) -> dict:
    contacts = []
    for item in output:
        contacts.append(
            {
                "id": item.id,
                "user_principal_name": item.userPrincipalName,
                "display_name": item.displayName,
                "email_address": item.emailAddress,
            }
        )

    results = [
        {
            "data": bool(contacts),
            "email": None,
            "contacts": contacts,
        }
    ]
    return {"results": results}


def resolve_name(
    params: ResolveNameParams, soar: SOARClient, asset: "Asset"
) -> list[ResolvedContact]:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = f"/users/{params.email_address}/people"
    api_params = {"$search": f'"{params.name}"', "$top": "50"}

    resp = helper.make_rest_call_helper(endpoint, params=api_params)
    people = resp.get("value", [])

    results = []
    for person in people:
        scored_emails = person.get("scoredEmailAddresses", [])
        email_addr = scored_emails[0].get("address") if scored_emails else None

        results.append(
            ResolvedContact(
                displayName=person.get("displayName"),
                emailAddress=email_addr,
                userPrincipalName=person.get("userPrincipalName"),
                id=person.get("id"),
            )
        )

    soar.set_message(f"Successfully resolved {len(results)} contacts")
    return results
