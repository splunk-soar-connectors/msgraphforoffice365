# Copyright (c) 2017-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper, serialize_complex_fields


class ListEventsParams(Params):
    user_id: str = Param(
        description="User ID/Principal name",
        required=False,
        primary=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
        default="",
    )
    group_id: str = Param(
        description="Group ID",
        required=False,
        primary=True,
        cef_types=["msgoffice365 group id"],
        default="",
    )
    filter: str = Param(
        description="OData query to filter/search for specific results",
        required=False,
        default="",
    )
    limit: int = Param(
        description="Maximum number of events to return", required=False, default=0
    )


class EventOutput(ActionOutput):
    id: str | None = None
    subject: str | None = None
    bodyPreview: str | None = None
    start: str | None = None
    end: str | None = None
    location: str | None = None
    organizer: str | None = None
    attendees: str | None = None
    isAllDay: bool | None = None
    isCancelled: bool | None = None
    webLink: str | None = None


COMPLEX_EVENT_FIELDS = ["start", "end", "location", "organizer", "attendees"]


@app.action(
    description="List events from user or group calendar", action_type="investigate"
)
def list_events(
    params: ListEventsParams, soar: SOARClient, asset: Asset
) -> list[EventOutput]:
    if params.limit is not None and params.limit < 0:
        raise ValueError("'limit' action parameter must be a non-negative integer")

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    if not params.user_id and not params.group_id:
        raise ValueError("Either user_id or group_id must be provided")

    if params.user_id:
        endpoint = f"/users/{params.user_id}/events"
    else:
        endpoint = f"/groups/{params.group_id}/events"

    api_params = {}
    if params.filter:
        if params.filter.startswith("$"):
            api_params.update(
                dict(
                    item.split("=", 1)
                    for item in params.filter.split("&")
                    if "=" in item
                )
            )
        else:
            api_params["$filter"] = params.filter
    if params.limit and params.limit > 0:
        api_params["$top"] = str(params.limit)

    events = []
    next_link = None
    while True:
        resp = helper.make_rest_call_helper(
            endpoint, params=api_params if api_params else None, nextLink=next_link
        )
        for event in resp.get("value", []):
            attendees = event.get("attendees", [])
            event["attendee_list"] = ", ".join(
                a.get("emailAddress", {}).get("name", "") for a in attendees
            )
            events.append(event)

        if params.limit and len(events) >= params.limit:
            events = events[: params.limit]
            break

        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break
        api_params = None

    events = [serialize_complex_fields(e, COMPLEX_EVENT_FIELDS) for e in events]
    soar.set_message(f"Successfully retrieved {len(events)} events")
    return [EventOutput(**e) for e in events]
