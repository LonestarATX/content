"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

import os
import ast
import json
import jwt
from datetime import datetime, timedelta
import requests
from typing import List

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}
    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

###############################################################################
# packages to handle IOerror
###############################################################################

if not demisto.params().get('proxy', False) \
        or demisto.params()['proxy'] == 'false':
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


"""GLOBAL VARS"""

VERIFY_CERT = True if not demisto.params().get('insecure') else False
KEY = demisto.params().get('key')
SECRET = demisto.params().get('secret')
DOMAIN = demisto.params().get('domain')
CUSTOMER_ID = demisto.params().get('customer_id')
FETCH_TIME = demisto.params().get('fetch_time')

"""HELPER FUNCTIONS"""

def generate_headers(key, secret):
    header = {}
    utcnow = datetime.utcnow()
    date = utcnow.strftime("%a, %d %b %Y %H:%M:%S GMT")
    auth_var = jwt.encode({'iss': key}, secret, algorithm='HS256')
    authorization = "Bearer " + str(auth_var)
    header['date'] = date
    header['Authorization'] = authorization
    return header


def restcall(method, api, **kwargs):

    header = generate_headers(KEY, SECRET)

    url = ("https://%s/public/api/customers/%s%s" %
           (DOMAIN, CUSTOMER_ID, api))

    try:
        request_func = getattr(requests, method)
    except AttributeError:
        return_error("Invalid method: {0}".format(method))

    try:
        response = request_func(
            url,
            headers=header,
            verify=VERIFY_CERT,
            **kwargs)
    except Exception as e:
        return_error("Error Connecting to server. Details: {0}".format(str(e)))

    return response.json()


def severity_to_int(level_string):
    level_int = 0
    if level_string == 'low':
        level_int = 1

    if level_string == 'medium':
        level_int = 2

    if level_string == 'high':
        level_int = 3

    return level_int


def remove_context_entries(context, context_entries_to_keep):
    for index in range(len(context)):
        for key in list(context[index]):
            if key not in context_entries_to_keep:
                context[index].pop(key, None)

    return context


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


# SAMPLE INTEGRATION CODE BELOW FOR EVALUATION / COMPARISON

#
#


###############################################################################
# packages to handle IOerror
###############################################################################

if not demisto.params().get('proxy', False) \
        or demisto.params()['proxy'] == 'false':
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


"""GLOBAL VARS"""

VERIFY_CERT = True if not demisto.params().get('insecure') else False
KEY = demisto.params().get('key')
SECRET = demisto.params().get('secret')
DOMAIN = demisto.params().get('domain')
CUSTOMER_ID = demisto.params().get('customer_id')
FETCH_TIME = demisto.params().get('fetch_time')

"""HELPER FUNCTIONS"""


def generate_headers(key, secret):
    header = {}
    utcnow = datetime.utcnow()
    date = utcnow.strftime("%a, %d %b %Y %H:%M:%S GMT")
    auth_var = jwt.encode({'iss': key}, secret, algorithm='HS256')
    authorization = "Bearer " + str(auth_var)
    header['date'] = date
    header['Authorization'] = authorization
    return header


def restcall(method, api, **kwargs):

    header = generate_headers(KEY, SECRET)

    url = ("https://%s/public/api/customers/%s%s" %
           (DOMAIN, CUSTOMER_ID, api))

    try:
        request_func = getattr(requests, method)
    except AttributeError:
        return_error("Invalid method: {0}".format(method))

    try:
        response = request_func(
            url,
            headers=header,
            verify=VERIFY_CERT,
            **kwargs)
    except Exception as e:
        return_error("Error Connecting to server. Details: {0}".format(str(e)))

    return response.json()


def severity_to_int(level_string):
    level_int = 0
    if level_string == 'low':
        level_int = 1

    if level_string == 'medium':
        level_int = 2

    if level_string == 'high':
        level_int = 3

    return level_int


def remove_context_entries(context, context_entries_to_keep):
    for index in range(len(context)):
        for key in list(context[index]):
            if key not in context_entries_to_keep:
                context[index].pop(key, None)

    return context



"""COMMAND FUNCTIONS"""






def uptycs_get_processes():
    """
    return process which are running or have run on a registered Uptycs asset
    """
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')
    query = "select * from processes"
    limit = demisto.args().get('limit')

    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = "%s WHERE upt_day = %s" % (query, uptday)

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is'),
        "upt_time": time
    }
    query = apply_equals_cuts(query, equal_cuts)

    like_cuts = {
        "upt_hostname": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    time_ago = demisto.args().get('time_ago')
    start_window = demisto.args().get('start_window')
    end_window = demisto.args().get('end_window')

    if time is None and (time_ago is not None or (start_window is not None
                         or end_window is not None)):
        begin, end = uptycs_parse_date_range(time_ago,
                                             start_window, end_window)
        query = apply_datetime_cuts(query, "upt_time", begin, end)

    query = ("%s ORDER BY upt_time DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_processes_command():
    query_results = uptycs_get_processes()
    human_readable = tableToMarkdown('Processes',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'name', 'path',
                                      'upt_time', 'parent', 'cmdline'])
    context = query_results.get('items')

    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid', 'name',
                               'path', 'upt_time', 'parent', 'cmdline',
                               'pgroup', 'cwd']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.Process': context
        }
    }

    return entry


def uptycs_get_process_events():
    """return process events which have executed on a \
        registered Uptycs asset"""
    http_method = 'post'
    api_call = '/query'
    time = demisto.args().get('time')
    query = "select * from process_events"
    limit = demisto.args().get('limit')

    if time is not None:
        day = time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))
    else:
        temp_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        day = temp_time.replace(" ", "-")
        day_list = day.split("-")
        uptday = int("%s%s%s" %
                     (str(day_list[0]), str(day_list[1]), str(day_list[2])))

    query = "%s WHERE upt_day = %s" % (query, uptday)

    equal_cuts = {
        "upt_asset_id": demisto.args().get('asset_id'),
        "upt_hostname": demisto.args().get('host_name_is'),
        "upt_time": time
    }
    query = apply_equals_cuts(query, equal_cuts)

    like_cuts = {
        "upt_hostname": demisto.args().get('host_name_like')
    }
    query = apply_like_cuts(query, like_cuts)

    time_ago = demisto.args().get('time_ago')
    start_window = demisto.args().get('start_window')
    end_window = demisto.args().get('end_window')

    if time is None and (time_ago is not None or (start_window is not None
                                                  or end_window is not None)):
        begin, end = uptycs_parse_date_range(time_ago,
                                             start_window, end_window)
        query = apply_datetime_cuts(query, "upt_time", begin, end)

    query = ("%s ORDER BY upt_time DESC" % query)

    if limit != -1 and limit is not None:
        query = ("%s LIMIT %s" % (query, limit))

    query_type = 'global'
    post_data = {
        'query': query,
        'queryType': query_type
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_get_process_events_command():
    query_results = uptycs_get_process_events()
    human_readable = tableToMarkdown('Process events',
                                     query_results.get('items'),
                                     ['upt_hostname', 'pid', 'path',
                                      'upt_time', 'parent', 'cmdline'])
    context = query_results.get('items')

    context_entries_to_keep = ['upt_hostname', 'upt_asset_id', 'pid', 'path',
                               'upt_time', 'parent', 'cmdline', 'cwd']

    if context is not None:
        remove_context_entries(context, context_entries_to_keep)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.ProcessEvents': context
        }
    }

    return entry





def uptycs_get_asset_tags():
    """set a tag on an asset"""
    http_method = 'get'
    api_call = ('/assets/%s' % demisto.args().get('asset_id'))
    return restcall(http_method, api_call).get('tags')


def uptycs_get_asset_tags_command():
    query_results = uptycs_get_asset_tags()
    human_readable = tableToMarkdown('Uptycs Asset Tags for asset id: %s' %
                                     demisto.args().get('asset_id'),
                                     query_results, 'Tags')
    context = query_results

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.AssetTags': context
        }
    }

    return entry


def uptycs_set_asset_tag():
    """set a tag on an asset"""
    http_method = 'get'
    api_call = ('/assets/%s' % demisto.args().get('asset_id'))
    tags = restcall(http_method, api_call).get('tags')

    tag_set = False
    tag_key = demisto.args().get('tag_key')
    tag_value = demisto.args().get('tag_value')
    for tag in tags:
        if tag_key in tag:
            temp_tag = tag.split('=')
            new_tag = temp_tag[0] + '=' + temp_tag[1] + ', ' + tag_value
            tags.remove(tag)
            tag_set = True

    if tag_set:
        tags.append(new_tag)
    elif tag_value is not None:
        tags.append(tag_key + '=' + tag_value)
    else:
        tags.append(tag_key)

    http_method = 'put'
    post_data = {
        'tags': tags
    }

    return restcall(http_method, api_call, json=post_data)


def uptycs_set_asset_tag_command():
    query_results = uptycs_set_asset_tag()
    human_readable = tableToMarkdown('Uptycs Asset Tag',
                                     query_results, ['hostName', 'tags'])
    context = query_results
    context_entries_to_keep = ['hostName', 'tags']

    if context is not None:
        for key in list(context):
            if key not in context_entries_to_keep:
                context.pop(key, None)

    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': query_results,
        'HumanReadable': human_readable,
        'EntryContext': {
            'Uptycs.AssetTags': context
        }
    }

    return entry





def fleet_test_module():
    """check whether FleetDM API responds correctly"""
    http_method = 'get'
    api_call = '/assets?limit=1'

    query_results = restcall(http_method, api_call)

    if query_results == 0:
        return False
    else:
        return True




def main():
    ###########################################################################
    # main function
    ###########################################################################

    try:
        if demisto.command() == 'uptycs-run-query':
            demisto.results(uptycs_run_query_command())

        if demisto.command() == 'uptycs-get-assets':
            demisto.results(uptycs_get_assets_command())

        if demisto.command() == 'uptycs-get-alerts':
            demisto.results(uptycs_get_alerts_command())

        if demisto.command() == 'uptycs-get-events':
            demisto.results(uptycs_get_events_command())

        if demisto.command() == 'uptycs-get-alert-rules':
            demisto.results(uptycs_get_alert_rules_command())

        if demisto.command() == 'uptycs-get-event-rules':
            demisto.results(uptycs_get_event_rules_command())

        if demisto.command() == 'uptycs-get-process-open-files':
            demisto.results(uptycs_get_process_open_files_command())

        if demisto.command() == 'uptycs-get-socket-events':
            demisto.results(uptycs_get_socket_events_command())

        if demisto.command() == 'uptycs-get-socket-event-information':
            demisto.results(uptycs_get_socket_event_information_command())

        if demisto.command() == 'uptycs-get-process-open-sockets':
            demisto.results(uptycs_get_process_open_sockets_command())

        if demisto.command() == 'uptycs-get-processes':
            demisto.results(uptycs_get_processes_command())

        if demisto.command() == 'uptycs-get-process-information':
            demisto.results(uptycs_get_process_information_command())



        if demisto.command() == 'test-module':
            # This is a test call made when user uses the integration test button.
            if fleet_test_module():
                demisto.results('ok')
            else:
                demisto.results('test failed')


        return_error(str(ex))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
