# File: office365_view.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


def get_ctx_result(provides, result):
    """ Function that parses data.

    :param result: result
    :param provides: action name
    :return: response data
    """

    file_attachment = []
    item_attachment = []
    reference_attachment = []
    other_attachment = []

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if summary:
        ctx_result['summary'] = summary
    ctx_result['action'] = provides
    if not data:
        ctx_result['data'] = {}
        return ctx_result

    if provides == "get email":
        for result in data:
            attachments = result.get('attachments', [])

            if not attachments:
                break

            for attachment in attachments:
                attachment_type = attachment.get('attachmentType', '')
                if attachment_type == "#microsoft.graph.fileAttachment":
                    file_attachment.append(attachment)
                elif attachment_type == "#microsoft.graph.itemAttachment":
                    item_attachment.append(attachment)
                elif attachment_type == "#microsoft.graph.referenceAttachment":
                    reference_attachment.append(attachment)
                else:
                    other_attachment.append(attachment)

            attachment_data = {
                'file_attachment': file_attachment,
                'item_attachment': item_attachment,
                'reference_attachment': reference_attachment,
                'other_attachment': other_attachment
            }

            result.update({'attachment_data': attachment_data})

    ctx_result['data'] = data

    return ctx_result


def display_view(provides, all_app_runs, context):
    """ Function that displays view.

    :param provides: action name
    :param context: context
    :param all_app_runs: all app runs
    :return: html page
    """

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(provides, result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == "list events":
       return_page = "office365_list_events.html"

    if provides == "get email":
       return_page = "office365_get_email.html"

    if provides == "run query":
       return_page = "office365_run_query.html"

    return return_page
