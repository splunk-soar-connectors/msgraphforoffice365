# File: process_email.py
#
# Copyright (c) 2017-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import email
import hashlib
import json
import mimetypes
import os
import random
import re
import shutil
import socket
import string
import tempfile
from builtins import str
from collections import OrderedDict
from copy import deepcopy
from email.header import decode_header, make_header

import magic
import phantom.app as phantom
import phantom.rules as phantom_rules
import phantom.utils as ph_utils
from bs4 import BeautifulSoup, UnicodeDammit
from requests.structures import CaseInsensitiveDict

from office365_consts import ERR_MSG_UNAVAILABLE

_container_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

_artifact_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

FILE_EXTENSIONS = {
    '.vmsn': ['os memory dump', 'vm snapshot file'],
    '.vmss': ['os memory dump', 'vm suspend file'],
    '.js': ['javascript'],
    '.doc': ['doc'],
    '.docx': ['doc'],
    '.xls': ['xls'],
    '.xlsx': ['xls'],
}

MAGIC_FORMATS = [
    (re.compile('^PE.* Windows'), ['pe file', 'hash']),
    (re.compile('^MS-DOS executable'), ['pe file', 'hash']),
    (re.compile('^PDF '), ['pdf']),
    (re.compile('^MDMP crash'), ['process dump']),
    (re.compile('^Macromedia Flash'), ['flash']),
]

MSG_DEFAULT_ARTIFACT_COUNT = 100
MSG_DEFAULT_CONTAINER_COUNT = 100
HASH_FIXED_PHANTOM_VERSION = "2.0.201"

PROC_EMAIL_JSON_FILES = "files"
PROC_EMAIL_JSON_BODIES = "bodies"
PROC_EMAIL_JSON_DATE = "date"
PROC_EMAIL_JSON_FROM = "from"
PROC_EMAIL_JSON_SUBJECT = "subject"
PROC_EMAIL_JSON_TO = "to"
PROC_EMAIL_JSON_START_TIME = "start_time"
PROC_EMAIL_JSON_EXTRACT_ATTACHMENTS = "extract_attachments"
PROC_EMAIL_JSON_EXTRACT_BODY = "add_body_to_header_artifacts"
PROC_EMAIL_JSON_EXTRACT_URLS = "extract_urls"
PROC_EMAIL_JSON_EXTRACT_IPS = "extract_ips"
PROC_EMAIL_JSON_EXTRACT_DOMAINS = "extract_domains"
PROC_EMAIL_JSON_EXTRACT_HASHES = "extract_hashes"
PROC_EMAIL_JSON_IPS = "ips"
PROC_EMAIL_JSON_HASHES = "hashes"
PROC_EMAIL_JSON_URLS = "urls"
PROC_EMAIL_JSON_DOMAINS = "domains"
PROC_EMAIL_JSON_MSG_ID = "message_id"
PROC_EMAIL_JSON_EMAIL_HEADERS = "email_headers"
PROC_EMAIL_CONTENT_TYPE_MESSAGE = "message/rfc822"

URI_REGEX = r"[Hh][Tt][Tt][Pp][Ss]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
EMAIL_REGEX = r"\b[A-Z0-9._%+-]+@+[A-Z0-9.-]+\.[A-Z]{2,}\b"
EMAIL_REGEX2 = r'".*"@[A-Z0-9.-]+\.[A-Z]{2,}\b'
HASH_REGEX = r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"
IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
IPV6_REGEX = r'\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))'
IPV6_REGEX += (r'|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|')
IPV6_REGEX += (r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|')
IPV6_REGEX += (r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|')
IPV6_REGEX += (r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|')
IPV6_REGEX += (r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|')
IPV6_REGEX += (r'(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*')


uri_regexc = re.compile(URI_REGEX)
email_regexc = re.compile(EMAIL_REGEX, re.IGNORECASE)
email_regexc2 = re.compile(EMAIL_REGEX2, re.IGNORECASE)
hash_regexc = re.compile(HASH_REGEX)
ip_regexc = re.compile(IP_REGEX)
ipv6_regexc = re.compile(IPV6_REGEX)


def _get_error_message_from_exception(e):
    """
    Get appropriate error message from the exception.
    :param e: Exception object
    :return: error message
    """

    error_code = None
    error_msg = ERR_MSG_UNAVAILABLE

    try:
        if hasattr(e, "args"):
            if len(e.args) > 1:
                error_code = e.args[0]
                error_msg = e.args[1]
            elif len(e.args) == 1:
                error_msg = e.args[0]
    except Exception:
        pass

    if not error_code:
        error_text = "Error Message: {}".format(error_msg)
    else:
        error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

    return error_text


class ProcessEmail(object):

    def __init__(self, base_connector, config):

        self._base_connector = base_connector
        self._config = config
        self._email_id_contains = list()
        self._container = dict()
        self._artifacts = list()
        self._attachments = list()
        self._headers_from_ews = list()
        self._attachments_from_msgraph = list()
        self._parsed_mail = None
        self._guid_to_hash = dict()
        self._tmp_dirs = list()

    def _get_file_contains(self, file_path):

        contains = []
        ext = os.path.splitext(file_path)[1]
        contains.extend(FILE_EXTENSIONS.get(ext, []))
        magic_str = magic.from_file(file_path)
        for regex, cur_contains in MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)

        return contains

    def _is_ip(self, input_ip):

        if ph_utils.is_ip(input_ip):
            return True

        if self.is_ipv6(input_ip):
            return True

        return False

    def is_ipv6(self, input_ip):

        try:
            socket.inet_pton(socket.AF_INET6, input_ip)
        except Exception:  # not a valid v6 address
            return False

        return True

    def _debug_print(self, *args):

        if self._base_connector and hasattr(self._base_connector, 'debug_print'):
            self._base_connector.debug_print(*args)

        return

    def _get_string(self, input_str, charset):
        try:
            if input_str:
                input_str = UnicodeDammit(input_str).unicode_markup.encode(charset).decode(charset)
        except Exception:
            try:
                input_str = str(make_header(decode_header(input_str)))
            except Exception:
                input_str = self._decode_uni_string(input_str, input_str)
            self._debug_print(
                "Error occurred while converting to string with specific encoding {}".format(input_str)
            )
        return input_str

    def _clean_url(self, url):

        url = url.strip('>),.]\r\n')

        # Check before splicing, find returns -1 if not found
        # _and_ you will end up splicing on -1 (incorrectly)
        if '<' in url:
            url = url[:url.find('<')]

        if '>' in url:
            url = url[:url.find('>')]

        url = url.rstrip(']')

        return url.strip()

    def _extract_urls_domains(self, file_data, urls, domains, parent_id=None):

        if not self._config[PROC_EMAIL_JSON_EXTRACT_DOMAINS] and not self._config[PROC_EMAIL_JSON_EXTRACT_URLS]:
            return

        # try to load the email
        try:
            soup = BeautifulSoup(file_data, "html.parser")
        except Exception as e:
            self._debug_print("Handled exception", e)
            return

        uris = []
        # get all tags that have hrefs
        links = soup.find_all(href=True)
        if links:
            # it's html, so get all the urls
            uris = [x['href'] for x in links if (not x['href'].startswith('mailto:'))]
            # work on the text part of the link, they might be http links different from the href
            # and were either missed by the uri_regexc while parsing text or there was no text counterpart
            # in the email
            uri_text = [self._clean_url(x.get_text()) for x in links]
            if uri_text:
                uri_text = [x for x in uri_text if x.startswith('http')]
                if uri_text:
                    uris.extend(uri_text)
        else:
            # Parse it as a text file
            uris = re.findall(uri_regexc, file_data)
            if uris:
                uris = [self._clean_url(x) for x in uris]

        if self._config[PROC_EMAIL_JSON_EXTRACT_URLS]:
            # add the uris to the urls
            unique_uris = set(uris)
            unique_uris = list(unique_uris)
            for uri in unique_uris:
                uri_dict = {'requestURL': uri, 'parentInternetMessageId': parent_id}
                urls.append(uri_dict)

        if self._config[PROC_EMAIL_JSON_EXTRACT_DOMAINS]:
            for uri in uris:
                domain = phantom.get_host_from_url(uri)
                if domain and not self._is_ip(domain):
                    domains.append({'destinationDnsDomain': domain, 'parentInternetMessageId': parent_id})
            # work on any mailto urls if present
            if links:
                mailtos = [x['href'] for x in links if (x['href'].startswith('mailto:'))]
                for curr_email in mailtos:
                    domain = curr_email[curr_email.find('@') + 1:]
                    if domain and (not self._is_ip(domain)):
                        if '?' in domain:
                            domain = domain[:domain.find('?')]
                        domains.append({'destinationDnsDomain': domain, 'parentInternetMessageId': parent_id})

        return

    def _get_ips(self, file_data, ips, parent_id=None):

        # First extract what looks like an IP from the file, this is a faster operation
        ips_in_mail = re.findall(ip_regexc, file_data)
        ip6_in_mail = re.findall(ipv6_regexc, file_data)

        if ip6_in_mail:
            for ip6_tuple in ip6_in_mail:
                ip6s = [x for x in ip6_tuple if x]
                ips_in_mail.extend(ip6s)

        # Now validate them
        if ips_in_mail:
            ips_in_mail = set(ips_in_mail)
            # match it with a slower and difficult regex.
            # TODO: Fix this with a one step approach.
            ips_in_mail = [x for x in ips_in_mail if self._is_ip(x)]
            if ips_in_mail:
                unique_ips = set(ips_in_mail)
                for ip in unique_ips:
                    ips.append({'sourceAddress': ip, 'parentInternetMessageId': parent_id})

    def _handle_body(self, body, parsed_mail, body_index, email_id):

        local_file_path = body['file_path']
        charset = body.get('charset')
        parent_id = None

        # parent_id = parsed_mail['email_headers'][body_index]['cef'].get('parentInternetMessageId')
        if 'True' in local_file_path:
            for item in parsed_mail['email_headers']:
                parent_id = item['cef'].get('parentInternetMessageId')
                if parent_id:
                    break

        ips = parsed_mail[PROC_EMAIL_JSON_IPS]
        hashes = parsed_mail[PROC_EMAIL_JSON_HASHES]
        urls = parsed_mail[PROC_EMAIL_JSON_URLS]
        domains = parsed_mail[PROC_EMAIL_JSON_DOMAINS]

        file_data = None
        try:
            with open(local_file_path, 'r') as f:   # noqa
                file_data = f.read()
        except Exception:
            with open(local_file_path, 'rb') as f:  # noqa
                file_data = f.read()
            self._base_connector.debug_print("Reading file data using binary mode")

        if file_data is None or len(file_data) == 0:
            return phantom.APP_ERROR

        self._parse_email_headers_as_inline(file_data, parsed_mail, charset, email_id)

        if self._config[PROC_EMAIL_JSON_EXTRACT_DOMAINS]:
            emails = []
            emails.extend(re.findall(email_regexc, file_data))
            emails.extend(re.findall(email_regexc2, file_data))

            for curr_email in emails:
                domain = curr_email[curr_email.rfind('@') + 1:]
                if domain and (not ph_utils.is_ip(domain)):
                    domains.append({'destinationDnsDomain': domain, 'parentInternetMessageId': parent_id})

        self._extract_urls_domains(file_data, urls, domains, parent_id)

        if self._config[PROC_EMAIL_JSON_EXTRACT_IPS]:
            self._get_ips(file_data, ips, parent_id)

        if self._config[PROC_EMAIL_JSON_EXTRACT_HASHES]:
            hashs_in_mail = re.findall(hash_regexc, file_data)
            if hashs_in_mail:
                unique_hashes = set(hashs_in_mail)
                for hash in unique_hashes:
                    hashes.append({'fileHash': hash, 'parentInternetMessageId': parent_id})

        return phantom.APP_SUCCESS

    def _add_artifacts(self, input_set, artifact_name, start_index, artifacts):

        added_artifacts = 0
        for item in input_set:
            # ignore empty entries
            if not item:
                continue

            artifact = {}
            artifact.update(_artifact_common)
            artifact['source_data_identifier'] = start_index + added_artifacts
            artifact['cef'] = item
            artifact['name'] = artifact_name
            self._debug_print('Artifact:', artifact)
            artifacts.append(artifact)
            added_artifacts += 1

        return added_artifacts

    def _parse_email_headers_as_inline(self, file_data, parsed_mail, charset, email_id):

        # remove the 'Forwarded Message' from the email text and parse it
        p = re.compile(r'.*Forwarded Message.*\r\n(.*)', re.IGNORECASE)
        email_text = p.sub(r'\1', file_data.strip()[:500])
        mail = email.message_from_string(email_text)

        self._parse_email_headers(parsed_mail, mail, charset, add_email_id=email_id)

        return phantom.APP_SUCCESS

    def _add_email_header_artifacts(self, email_header_artifacts, start_index, artifacts):

        added_artifacts = 0
        for artifact in email_header_artifacts:
            artifact['source_data_identifier'] = start_index + added_artifacts
            artifacts.append(artifact)
            added_artifacts += 1

        return added_artifacts

    def _create_artifacts(self, parsed_mail):

        # get all the artifact data in their own list objects
        ips = [dict(t) for t in set([tuple(d.items()) for d in parsed_mail[PROC_EMAIL_JSON_IPS]])]
        hashes = [dict(t) for t in set([tuple(d.items()) for d in parsed_mail[PROC_EMAIL_JSON_HASHES]])]
        urls = [dict(t) for t in set([tuple(d.items()) for d in parsed_mail[PROC_EMAIL_JSON_URLS]])]
        domains = [dict(t) for t in set([tuple(d.items()) for d in parsed_mail[PROC_EMAIL_JSON_DOMAINS]])]
        email_headers = parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS]

        # set the default artifact dict

        artifact_id = 0

        # add artifacts
        added_artifacts = self._add_artifacts(ips, 'IP Artifact', artifact_id, self._artifacts)
        artifact_id += added_artifacts

        added_artifacts = self._add_artifacts(hashes, 'Hash Artifact', artifact_id, self._artifacts)
        artifact_id += added_artifacts

        added_artifacts = self._add_artifacts(urls, 'URL Artifact', artifact_id, self._artifacts)
        artifact_id += added_artifacts

        added_artifacts = self._add_artifacts(domains, 'Domain Artifact', artifact_id, self._artifacts)
        artifact_id += added_artifacts

        added_artifacts = self._add_email_header_artifacts(email_headers, artifact_id, self._artifacts)
        email_headers = email_headers
        artifact_id += added_artifacts

        return phantom.APP_SUCCESS

    def _decode_uni_string(self, input_str, def_name):

        # try to find all the decoded strings, we could have multiple decoded strings
        # or a single decoded string between two normal strings separated by \r\n
        # YEAH...it could get that messy
        encoded_strings = re.findall(r'=\?.*\?=', input_str, re.I)

        # return input_str as is, no need to do any conversion
        if not encoded_strings:
            return input_str

        # get the decoded strings
        try:
            decoded_strings = [decode_header(x)[0] for x in encoded_strings]
            decoded_strings = [{'value': x[0], 'encoding': x[1]} for x in decoded_strings]
        except Exception as e:
            error_msg = _get_error_message_from_exception(e)
            self._debug_print("Decoding: {0}. {1}".format(encoded_strings, error_msg))
            return def_name

        # convert to dict for safe access, if it's an empty list, the dict will be empty
        decoded_strings = dict(enumerate(decoded_strings))

        new_str = ''
        new_str_create_count = 0
        for i, encoded_string in enumerate(encoded_strings):

            decoded_string = decoded_strings.get(i)

            if not decoded_string:
                # nothing to replace with
                continue

            value = decoded_string.get('value')
            encoding = decoded_string.get('encoding')

            if not encoding or not value:
                # nothing to replace with
                continue

            try:
                # Some non-ascii characters were causing decoding issue with
                # the UnicodeDammit and working correctly with the decode function.
                # keeping previous logic in the except block incase of failure.
                if value:
                    value = value.decode(encoding)
                    new_str += value
                    new_str_create_count += 1
            except Exception:
                try:
                    if encoding != 'utf-8':
                        value = str(value, encoding)
                except Exception:
                    pass
                try:
                    # commenting the existing approach due to a new approach being deployed below
                    # substitute the encoded string with the decoded one
                    # input_str = input_str.replace(encoded_string, value)

                    # make new string instead of replacing in the input string because issue find in PAPP-9531
                    if value:
                        # value = UnicodeDammit(value).unicode_markup
                        new_str += UnicodeDammit(value).unicode_markup
                        new_str_create_count += 1
                except Exception:
                    pass

        # replace input string with new string because issue find in PAPP-9531
        if new_str and new_str_create_count == len(encoded_strings):
            self.debug_print("Creating a new string entirely from the encoded_strings and assigning into input_str")
            input_str = new_str

        return input_str

    def _get_container_name(self, parsed_mail, email_id):

        # Create the default name
        def_cont_name = "Email ID: {0}".format(email_id)

        # get the subject from the parsed mail
        subject = parsed_mail.get(PROC_EMAIL_JSON_SUBJECT)

        # if no subject then return the default
        if not subject:
            return def_cont_name

        return self._decode_uni_string(subject, def_cont_name)

    def _handle_if_body(self, content_disp, content_id, content_type, part, bodies, file_path):

        process_as_body = False

        # if content disposition is None then assume that it is
        if content_disp is None:
            process_as_body = True
        # if content disposition is inline
        elif content_disp.lower().strip() == 'inline':
            if 'text/html' in content_type or 'text/plain' in content_type:
                process_as_body = True

        if not process_as_body:
            return (phantom.APP_SUCCESS, True)

        part_payload = part.get_payload(decode=True)

        if not part_payload:
            return (phantom.APP_SUCCESS, False)

        with open(file_path, 'wb') as f:    # noqa
            f.write(part_payload)

        bodies.append({'file_path': file_path, 'charset': part.get_content_charset()})

        return (phantom.APP_SUCCESS, False)

    def _handle_attachment(self, part, tmp_dir, file_name, file_path):

        files = self._parsed_mail[PROC_EMAIL_JSON_FILES]

        if not self._config[PROC_EMAIL_JSON_EXTRACT_ATTACHMENTS]:
            return phantom.APP_SUCCESS

        part_base64_encoded = part.get_payload()

        headers = self._get_email_headers_from_part(part)

        attach_meta_info = dict()

        if headers:
            attach_meta_info = {'headers': dict(headers)}

        for curr_attach in self._attachments_from_msgraph:

            if curr_attach.get('should_ignore', False):
                continue

            try:
                attach_content = curr_attach['content']
            except Exception:
                continue

            if attach_content.strip().replace('\r\n', '') == part_base64_encoded.strip().replace('\r\n', ''):
                attach_meta_info.update(dict(curr_attach))
                del attach_meta_info['content']
                curr_attach['should_ignore'] = True

        part_payload = part.get_payload(decode=True)
        if not part_payload:
            return phantom.APP_SUCCESS

        try:
            with open(file_path, 'wb') as f:    # noqa
                f.write(part_payload)
            files.append({'file_name': file_name, 'file_path': file_path, 'meta_info': attach_meta_info})
        except IOError as ioerr:
            error_msg = _get_error_message_from_exception(ioerr)
            if "File name too long" in error_msg:
                self.write_with_new_filename(tmp_dir, part_payload, files, file_name, as_byte=False)
            else:
                self._debug_print('Failed to write file: {}'.format(ioerr))

    def write_with_new_filename(self, tmp_dir, data, dict_to_fill, file_name, as_byte=False):
        try:
            _, file_extension = os.path.splitext(file_name)
            random_suffix = '_' + ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(16))
            new_file_name = "ph_long_file_name_{0}{1}".format(random_suffix, file_extension)
            full_path = os.path.join(tmp_dir, new_file_name)

            with open(full_path, 'wb') as f:    # noqa
                if as_byte:
                    f.write(data.as_bytes())
                else:
                    f.write(data)
            dict_to_fill.append({'file_name': new_file_name, 'file_path': full_path})
        except Exception as e:
            self._base_connector.debug_print('Exception while writing file: {}'.format(e))

    def _handle_part(self, part, part_index, tmp_dir, extract_attach, parsed_mail, child=False):

        bodies = parsed_mail[PROC_EMAIL_JSON_BODIES]

        # get the file_name
        file_name = part.get_filename()
        content_disp = part.get('Content-Disposition')
        content_type = part.get('Content-Type')
        content_id = part.get('Content-ID')

        if file_name is None:
            # init name and extension to default values
            name = "part_{0}_{1}".format(part_index, child)
            extension = ".{0}".format(part_index)

            # Try to create an extension from the content type if possible
            if content_type is not None:
                extension = mimetypes.guess_extension(re.sub(';.*', '', content_type))

            # Try to create a name from the content id if possible
            if content_id is not None:
                name = content_id

            file_name = "{0}{1}".format(name, extension)
        else:
            file_name = self._decode_uni_string(file_name, file_name)

        # Remove any chars that we don't want in the name
        file_path = "{0}/{1}_{2}_{3}".format(tmp_dir, part_index,
                file_name.translate(None, ''.join(['<', '>', ' '])), child)

        self._debug_print("file_path: {0}".format(file_path))

        # is the part representing the body of the email
        status, process_further = self._handle_if_body(content_disp, content_id, content_type, part, bodies, file_path)

        if not process_further:
            return phantom.APP_SUCCESS

        # is this another email as an attachment
        if content_type is not None and content_type.find(PROC_EMAIL_CONTENT_TYPE_MESSAGE) != -1:
            return phantom.APP_SUCCESS

        # This is an attachment and it's not an email
        self._handle_attachment(part, tmp_dir, file_name, file_path)

        return phantom.APP_SUCCESS

    def _update_headers(self, headers):

        # compare the various values of the passed header (param: headers)
        # to the header that the class got self._headers_from_ews
        if not self._headers_from_ews:
            return phantom.APP_SUCCESS

        if not headers:
            return phantom.APP_SUCCESS

        headers_ci = CaseInsensitiveDict(headers)

        for curr_header_lower in self._headers_from_ews:
            if headers_ci.get('message-id', 'default_value1').strip() == curr_header_lower.get('message-id', 'default_value2').strip():
                # the headers match with the one that we got from the ews API, so update it
                headers.update(curr_header_lower)

        return phantom.APP_SUCCESS

    def _get_email_headers_from_part(self, part, charset=None):

        email_headers = list(part.items())

        # TODO: the next 2 ifs can be condensed to use 'or'
        if charset is None:
            charset = part.get_content_charset()

        if charset is None:
            charset = 'utf8'

        if not email_headers:
            return {}

        # Convert the header tuple into a dictionary
        headers = CaseInsensitiveDict()
        [headers.update({x[0]: str(x[1], charset)}) for x in email_headers]

        # Handle received seperately
        received_headers = [str(x[1], charset) for x in email_headers if x[0].lower() == 'received']

        if received_headers:
            headers['Received'] = received_headers

        # handle the subject string, if required add a new key
        subject = headers.get('Subject')
        if subject:
            if type(subject) == str:
                headers['decodedSubject'] = self._decode_uni_string(subject.encode('utf8'), subject)

        return headers

    def _parse_email_headers(self, parsed_mail, part, charset=None, add_email_id=None):

        email_header_artifacts = parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS]

        headers = self._get_email_headers_from_part(part, charset)

        if not headers:
            return 0

        # Parse email keys first
        cef_artifact = {}
        cef_types = {}

        if headers.get('From'):
            emails = headers['From']
            if emails:
                cef_artifact.update({'fromEmail': emails})

        if headers.get('To'):
            emails = headers['To']
            if emails:
                cef_artifact.update({'toEmail': emails})

        # if the header did not contain any email addresses then ignore this artifact
        message_id = headers.get('message-id')
        if not cef_artifact and message_id is None:
            return 0

        cef_types.update({'fromEmail': ['email'], 'toEmail': ['email']})

        if headers:
            self._update_headers(headers)
            cef_artifact['emailHeaders'] = dict(headers)

        for curr_key in list(cef_artifact['emailHeaders'].keys()):
            if curr_key.lower().startswith('body'):
                curr_value = cef_artifact['emailHeaders'].pop(curr_key)
                if self._config.get(PROC_EMAIL_JSON_EXTRACT_BODY, False):
                    cef_artifact.update({curr_key: curr_value})
            elif curr_key == 'parentInternetMessageId':
                curr_value = cef_artifact['emailHeaders'].pop(curr_key)
                cef_artifact.update({curr_key: curr_value})
            elif curr_key == 'parentGuid':
                curr_value = cef_artifact['emailHeaders'].pop(curr_key)
                cef_artifact.update({curr_key: curr_value})
            elif curr_key == 'emailGuid':
                curr_value = cef_artifact['emailHeaders'].pop(curr_key)
                cef_artifact.update({curr_key: curr_value})

        # Adding the email id as a cef artifact crashes the UI when trying to show the action dialog box
        # so not adding this right now. All the other code to process the emailId is there, but the refraining
        # from adding the emailId
        # add_email_id = False
        if add_email_id:
            cef_artifact['emailId'] = add_email_id
            if self._email_id_contains:
                cef_types.update({'emailId': self._email_id_contains})

        artifact = {}
        artifact.update(_artifact_common)
        artifact['name'] = 'Email Artifact'
        artifact['severity'] = self._base_connector.get_config().get('container_severity', 'medium')
        artifact['cef'] = cef_artifact
        artifact['cef_types'] = cef_types
        email_header_artifacts.append(artifact)

        return len(email_header_artifacts)

    def _handle_mail_object(self, mail, email_id, rfc822_email, tmp_dir, start_time_epoch):

        self._parsed_mail = OrderedDict()

        # Create a tmp directory for this email, will extract all files here
        tmp_dir = tmp_dir
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)

        extract_attach = self._config[PROC_EMAIL_JSON_EXTRACT_ATTACHMENTS]

        charset = mail.get_content_charset()

        if charset is None:
            charset = 'utf-8'

        # Extract fields and place it in a dictionary
        self._parsed_mail[PROC_EMAIL_JSON_SUBJECT] = mail.get('Subject', '')
        self._parsed_mail[PROC_EMAIL_JSON_FROM] = mail.get('From', '')
        self._parsed_mail[PROC_EMAIL_JSON_TO] = mail.get('To', '')
        self._parsed_mail[PROC_EMAIL_JSON_DATE] = mail.get('Date', '')
        self._parsed_mail[PROC_EMAIL_JSON_MSG_ID] = mail.get('Message-ID', '')
        self._parsed_mail[PROC_EMAIL_JSON_FILES] = files = []
        self._parsed_mail[PROC_EMAIL_JSON_BODIES] = bodies = []
        self._parsed_mail[PROC_EMAIL_JSON_START_TIME] = start_time_epoch
        self._parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS] = []

        # parse the parts of the email
        if mail.is_multipart():
            child = False
            message_id = None
            for i, part in enumerate(mail.walk()):
                add_email_id = None
                if i == 0:
                    add_email_id = email_id

                self._parse_email_headers(self._parsed_mail, part, add_email_id=add_email_id)
                if message_id is None and part.get('Message-ID'):
                    message_id = part.get('Message-ID')
                    child = False
                elif message_id and part.get('Message-ID'):
                    child = True

                self._debug_print("part: {0}".format(part.__dict__))
                self._debug_print("part type", type(part))
                if part.is_multipart():
                    continue
                try:
                    ret_val = self._handle_part(part, i, tmp_dir, extract_attach, self._parsed_mail, child)
                except Exception as e:
                    self._debug_print("ErrorExp in _handle_part # {0}".format(i), e)
                    continue

                if phantom.is_fail(ret_val):
                    continue

        else:
            print('else')
            self._parse_email_headers(self._parsed_mail, mail, add_email_id=email_id)
            # parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS].append(mail.items())
            file_path = "{0}/part_1.text".format(tmp_dir)
            with open(file_path, 'wb') as f:    # noqa
                f.write(mail.get_payload(decode=True))
            bodies.append({'file_path': file_path, 'charset': mail.get_content_charset()})

        # get the container name
        container_name = self._get_container_name(self._parsed_mail, email_id)

        if container_name is None:
            return phantom.APP_ERROR

        # Add the container
        # first save the container, to do that copy things from parsed_mail to a new object
        container = {}
        container_data = dict(self._parsed_mail)

        # delete the header info, we dont make it a part of the container json
        del(container_data[PROC_EMAIL_JSON_EMAIL_HEADERS])
        container.update(_container_common)
        self._container['source_data_identifier'] = email_id
        self._container['name'] = container_name
        self._container['data'] = {'raw_email': rfc822_email}

        # Create the sets before handling the bodies If both the bodies add the same ip
        # only one artifact should be created

        # Changing to a list due to add parent identifier in each artifact
        self._parsed_mail[PROC_EMAIL_JSON_IPS] = list()
        self._parsed_mail[PROC_EMAIL_JSON_HASHES] = list()
        self._parsed_mail[PROC_EMAIL_JSON_URLS] = list()
        self._parsed_mail[PROC_EMAIL_JSON_DOMAINS] = list()

        # For bodies
        for i, body in enumerate(bodies):
            if not body:
                continue

            try:
                self._handle_body(body, self._parsed_mail, i, email_id)
            except Exception as e:
                self._debug_print("ErrorExp in _handle_body # {0}: {1}".format(i, str(e)))
                continue

        # Files
        self._attachments.extend(files)

        self._create_artifacts(self._parsed_mail)

        return phantom.APP_SUCCESS

    def _set_email_id_contains(self, email_id):

        if not self._base_connector:
            return

        try:
            email_id = self._get_string(email_id, 'utf-8')
        except Exception:
            email_id = str(email_id)

        if ph_utils.is_sha1(email_id):
            self._email_id_contains = ["vault id"]
        else:
            self._email_id_contains = ["msgoffice365 message id"]
        return

    def _int_process_email(self, rfc822_email, email_id, start_time_epoch):

        mail = email.message_from_string(rfc822_email)

        ret_val = phantom.APP_SUCCESS

        tmp_dir = tempfile.mkdtemp(prefix='ph_email_phmsgo365')
        self._tmp_dirs.append(tmp_dir)

        try:
            ret_val = self._handle_mail_object(mail, email_id, rfc822_email, tmp_dir, start_time_epoch)
        except Exception as e:
            message = "ErrorExp in self._handle_mail_object: {0}".format(e)
            self._debug_print(message)
            return (phantom.APP_ERROR, message, [])

        results = [{'container': self._container, 'artifacts': self._artifacts, 'files': self._attachments, 'temp_directory': tmp_dir}]

        return (ret_val, "Email Parsed", results)

    def process_email(self, rfc822_email, email_id, epoch, container_id=None, email_headers=None, attachments_data=None):

        if email_headers:
            for curr_header in email_headers:
                self._headers_from_ews.append(CaseInsensitiveDict(curr_header))

        if self._config[PROC_EMAIL_JSON_EXTRACT_ATTACHMENTS] and attachments_data is not None:
            self._attachments_from_msgraph = attachments_data

        try:
            self._set_email_id_contains(email_id)
        except Exception:
            pass

        ret_val, message, results = self._int_process_email(rfc822_email, email_id, epoch)

        if not ret_val:
            self._del_tmp_dirs()
            return (phantom.APP_ERROR, message)

        try:
            self._parse_results(results, container_id)
        except Exception as e:
            # delete any temp directories that were created by the email parsing function
            self._del_tmp_dirs()
            self._base_connector.debug_print(_get_error_message_from_exception(e))
            return phantom.APP_ERROR, "Error occurred while parsing the results"

        return (phantom.APP_SUCCESS, "Email Processed")

    def _save_ingested(self, container, using_dummy):
        if using_dummy:
            cid = container['id']
            artifacts = container['artifacts']
            for artifact in artifacts:
                artifact['container_id'] = cid
            ret_val, message, ids = self._base_connector.save_artifacts(artifacts)
            self._base_connector.debug_print(
                "save_artifacts returns, value: {0}, reason: {1}".format(
                    ret_val,
                    message
                )
            )

        else:
            ret_val, message, cid = self._base_connector.save_container(container)
            self._base_connector.debug_print(
                "save_container (with artifacts) returns, value: {0}, reason: {1}, id: {2}".format(
                    ret_val,
                    message,
                    cid
                )
            )

        return ret_val, message, cid

    def _handle_save_ingested(self, artifacts, container, container_id, files):
        # One of either container or container_id will be set to None
        using_dummy = False

        if container_id:
            # We are adding artifacts to an existing container
            using_dummy = True
            container = {
                'name': 'Dummy Container',
                'dummy': True,
                'id': container_id,
                'artifacts': artifacts,
            }
        else:
            # Create a new container
            container['artifacts'] = artifacts

        if hasattr(self._base_connector, '_preprocess_container'):
            container = self._base_connector._preprocess_container(container)

        for artifact in list([x for x in container.get('artifacts', []) if not x.get('source_data_identifier')]):
            self._set_sdi(artifact)

        if files and container.get('artifacts'):
            # Make sure the playbook only runs once
            # We will instead set run_automation on the last vault artifact which is added
            container['artifacts'][-1]['run_automation'] = False

        ret_val, message, container_id = self._save_ingested(container, using_dummy)

        if phantom.is_fail(ret_val):
            message = "Failed to save ingested artifacts, error msg: {0}".format(message)
            self._base_connector.debug_print(message)
            return

        if not container_id:
            message = "save_container did not return a container_id"
            self._base_connector.debug_print(message)
            return

        vault_artifacts_added = 0

        last_file = len(files) - 1
        for i, curr_file in enumerate(files):
            run_automation = True if i == last_file else False
            ret_val, added_to_vault = self._handle_file(
                curr_file, container_id, vault_artifacts_added, run_automation
            )

            if added_to_vault:
                vault_artifacts_added += 1

        return

    def _parse_results(self, results, container_id=None):

        param = self._base_connector.get_current_param()

        container_count = MSG_DEFAULT_CONTAINER_COUNT
        # artifact_count = MSG_DEFAULT_ARTIFACT_COUNT

        if param:
            container_count = param.get(phantom.APP_JSON_CONTAINER_COUNT, MSG_DEFAULT_CONTAINER_COUNT)
            # artifact_count = param.get(phantom.APP_JSON_ARTIFACT_COUNT, EWS_DEFAULT_ARTIFACT_COUNT)

        results = results[:container_count]

        for result in results:

            if container_id is None:

                container = result.get('container')

                if not container:
                    continue

                container.update(_container_common)

            else:
                container = None

            # run a loop to first set the sdi which will create the hash
            artifacts = result.get('artifacts', [])
            for j, artifact in enumerate(artifacts):

                if not artifact:
                    continue

                self._set_sdi(artifact)

            if not artifacts:
                continue

            len_artifacts = len(artifacts)

            for j, artifact in enumerate(artifacts):

                if not artifact:
                    continue

                # if it is the last artifact of the last container
                if (j + 1) == len_artifacts:
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

                cef_artifact = artifact.get('cef')
                if 'parentGuid' in cef_artifact:
                    parent_guid = cef_artifact.pop('parentGuid')
                    if parent_guid in self._guid_to_hash:
                        cef_artifact['parentSourceDataIdentifier'] = self._guid_to_hash[parent_guid]
                if 'emailGuid' in cef_artifact:
                    # cef_artifact['emailGuid'] = self._guid_to_hash[cef_artifact['emailGuid']]
                    del cef_artifact['emailGuid']

            self._handle_save_ingested(artifacts, container, container_id, result.get('files'))

        # delete any temp directories that were created by the email parsing function
        [shutil.rmtree(x['temp_directory'], ignore_errors=True) for x in results if x.get('temp_directory')]

        return self._base_connector.set_status(phantom.APP_SUCCESS)

    def _add_vault_hashes_to_dictionary(self, cef_artifact, vault_id):

        success, message, vault_info = phantom_rules.vault_info(vault_id=vault_id)

        if not vault_info:
            return (phantom.APP_ERROR, "Vault ID not found")

        # The return value is a list, each item represents an item in the vault
        # matching the vault id, the info that we are looking for (the hashes)
        # will be the same for every entry, so just access the first one
        try:
            metadata = vault_info[0].get('metadata')
        except Exception:
            return (phantom.APP_ERROR, "Failed to get vault item metadata")

        try:
            cef_artifact['fileHashSha256'] = metadata['sha256']
        except Exception:
            pass

        try:
            cef_artifact['fileHashMd5'] = metadata['md5']
        except Exception:
            pass

        try:
            cef_artifact['fileHashSha1'] = metadata['sha1']
        except Exception:
            pass

        return (phantom.APP_SUCCESS, "Mapped hash values")

    def _handle_file(self, curr_file, container_id):

        file_name = curr_file.get('file_name')

        local_file_path = curr_file['file_path']

        contains = self._get_file_contains(local_file_path)

        # lets move the data into the vault
        vault_attach_dict = {}

        if not file_name:
            file_name = os.path.basename(local_file_path)

        self._base_connector.debug_print("Vault file name: {0}".format(file_name))

        vault_attach_dict[phantom.APP_JSON_ACTION_NAME] = self._base_connector.get_action_name()
        vault_attach_dict[phantom.APP_JSON_APP_RUN_ID] = self._base_connector.get_app_run_id()

        vault_add_success = False
        vault_add_msg = ""
        vault_id = None

        file_name = self._decode_uni_string(file_name, file_name)

        try:
            vault_add_success, vault_add_msg, vault_id = phantom_rules.vault_add(
                file_location=local_file_path,
                container=container_id,
                file_name=file_name,
                metadata=vault_attach_dict
            )
        except Exception as e:
            self._debug_print(phantom.APP_ERR_FILE_ADD_TO_VAULT.format(e))
            return (phantom.APP_ERROR, phantom.APP_ERROR)

        if not vault_add_success:
            self._debug_print("Failed to add file to Vault: {0}".format(vault_add_msg))
            return (phantom.APP_ERROR, phantom.APP_ERROR)

        # add the vault id artifact to the container
        cef_artifact = curr_file.get('meta_info', {})
        if file_name:
            cef_artifact.update({'fileName': file_name})

        if vault_id:
            cef_artifact.update({'vaultId': vault_id,
                'cs6': vault_id,
                'cs6Label': 'Vault ID'})

            # now get the rest of the hashes and add them to the cef artifact
            self._add_vault_hashes_to_dictionary(cef_artifact, vault_id)

        if not cef_artifact:
            return (phantom.APP_SUCCESS, phantom.APP_ERROR)

        artifact = {}
        artifact.update(_artifact_common)
        artifact['container_id'] = container_id
        artifact['name'] = 'Vault Artifact'
        artifact['cef'] = cef_artifact
        if contains:
            artifact['cef_types'] = {'vaultId': contains, 'cs6': contains}
        self._set_sdi(artifact)

        if 'parentGuid' in cef_artifact:
            parent_guid = cef_artifact.pop('parentGuid')
            cef_artifact['parentSourceDataIdentifier'] = self._guid_to_hash[parent_guid]

        ret_val, status_string, artifact_id = self._base_connector.save_artifact(artifact)
        self._base_connector.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

        return (phantom.APP_SUCCESS, ret_val)

    def _set_sdi(self, input_dict):

        if 'source_data_identifier' in input_dict:
            del input_dict['source_data_identifier']

        input_dict_hash = input_dict

        cef = input_dict.get('cef')

        curr_email_guid = None

        if cef is not None:
            if 'parentGuid' in cef or 'emailGuid' in cef:
                # make a copy since the dictionary will have to be different
                input_dict_hash = deepcopy(input_dict)
                cef = input_dict_hash['cef']
                if 'parentGuid' in cef:
                    del cef['parentGuid']
                curr_email_guid = cef.get('emailGuid')
                if curr_email_guid is not None:
                    del cef['emailGuid']

        input_dict['source_data_identifier'] = self._create_dict_hash(input_dict_hash)

        if curr_email_guid:
            self._guid_to_hash[curr_email_guid] = input_dict['source_data_identifier']

        return phantom.APP_SUCCESS

    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self._base_connector.debug_print('Handled exception in _create_dict_hash', e)
            return None

        fips_enabled = self._base_connector._get_fips_enabled()
        if not fips_enabled:
            return hashlib.md5(input_dict_str).hexdigest()

        return hashlib.sha256(input_dict_str).hexdigest()

    def _del_tmp_dirs(self):
        """Remove any tmp_dirs that were created."""
        for tmp_dir in self._tmp_dirs:
            shutil.rmtree(tmp_dir, ignore_errors=True)
