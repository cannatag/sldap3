"""
"""

# Created on 2015.03.12
#
# Author: Giovanni Cannata
#
# Copyright 2015 Giovanni Cannata
#
# This file is part of sldap3.
#
# sldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# sldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

import asyncio
from ldap3 import SEQUENCE_TYPES, LDAPControlsError
from ldap3.operation.abandon import abandon_request_to_dict
from ldap3.operation.bind import bind_request_to_dict
from ldap3.operation.add import add_request_to_dict
from ldap3.operation.compare import compare_request_to_dict
from ldap3.operation.delete import delete_request_to_dict
from ldap3.operation.extended import extended_request_to_dict
from ldap3.operation.modify import modify_request_to_dict
from ldap3.operation.modifyDn import modify_dn_request_to_dict
from ldap3.operation.search import search_request_to_dict
from pyasn1.codec.ber import decoder, encoder

from ldap3.protocol.rfc4511 import LDAPMessage, BindRequest, ResultCode, LDAPDN, BindResponse, LDAPString, Referral, \
    ServerSaslCreds, MessageID, ProtocolOp, Controls, Control
from ldap3.protocol.rfc2696 import RealSearchControlValue
from ldap3.protocol.oid import Oids
from core.user import User

clients = dict()
identities = dict()


def build_controls_list(controls):
    """
    controls is a list of tuple
    each tuple must have 3 elements: the control OID, the criticality, the value
    criticality must be a boolean
    """
    if not controls:
        return None

    if not isinstance(controls, SEQUENCE_TYPES):
        raise LDAPControlsError('controls must be a list')

    built_controls = Controls()
    for idx, control in enumerate(controls):
        if len(control) == 3 and isinstance(control[1], bool):
            built_control = Control()
            built_control['controlType'] = control[0]
            built_control['criticality'] = control[1]
            built_control['controlValue'] = control[2]
            built_controls.setComponentByPosition(idx, built_control)
        else:
            raise LDAPControlsError('control must be a tuple of 3 elements: controlType, criticality (boolean) and controlValue')

    return built_controls


def decode_control(control):
    """
    decode control, return a 2-element tuple where the first element is the control oid
    and the second element is a dictionary with description (from Oids), criticality and decoded control value
    """
    control_type = str(control['controlType'])
    criticality = bool(control['criticality'])
    control_value = bytes(control['controlValue'])
    if control_type == '1.2.840.113556.1.4.319':  # simple paged search as per RFC2696
        control_resp, unprocessed = decoder.decode(control_value, asn1Spec=RealSearchControlValue())
        control_value = dict()
        control_value['size'] = int(control_resp['size'])
        control_value['cookie'] = bytes(control_resp['cookie'])
        if unprocessed:
            pass

    return control_type, {'description': Oids.get(control_type, ''), 'criticality': criticality, 'value': control_value}


def decode_request(ldap_message):
    message_type = ldap_message.getComponentByName('protocolOp').getName()
    component = ldap_message['protocolOp'].getComponent()
    if message_type == 'bindRequest':
        result = bind_request_to_dict(component)
    elif message_type == 'unbindRequest':
        result = dict()
    elif message_type == 'addRequest':
        result = add_request_to_dict(component)
    elif message_type == 'compareRequest':
        result = compare_request_to_dict(component)
    elif message_type == 'delRequest':
        result = delete_request_to_dict(component)
    elif message_type == 'extendedReq':
        result = extended_request_to_dict(component)
    elif message_type == 'modifyRequest':
        result = modify_request_to_dict(component)
    elif message_type == 'modDNRequest':
        result = modify_dn_request_to_dict(component)
    elif message_type == 'searchRequest':
        result = search_request_to_dict(component)
    elif message_type == 'abandonRequest':
        result = abandon_request_to_dict(component)
    else:
        raise Exception('unknown request')
    result['type'] = message_type
    return result


def compute_ldap_message_size(data):
    """
    Compute LDAP Message size according to BER definite length rules
    Returns -1 if too few data to compute message length
    """
    if isinstance(data, str):  # fix for Python 2, data is string not bytes
        data = bytearray(data)  # Python 2 bytearray is equivalent to Python 3 bytes

    ret_value = -1
    if len(data) > 2:
        if data[1] <= 127:  # BER definite length - short form. Highest bit of byte 1 is 0, message length is in the last 7 bits - Value can be up to 127 bytes long
            ret_value = data[1] + 2
        else:  # BER definite length - long form. Highest bit of byte 1 is 1, last 7 bits counts the number of following octets containing the value length
            bytes_length = data[1] - 128
            if len(data) >= bytes_length + 2:
                value_length = 0
                cont = bytes_length
                for byte in data[2:2 + bytes_length]:
                    cont -= 1
                    value_length += byte * (256 ** cont)
                ret_value = value_length + 2 + bytes_length

    return ret_value


@asyncio.coroutine
def do_bind_operation(message_id, dict_req, user):
    print('do bind operation')
    response = BindResponse()
    response['resultCode'] = ResultCode(0)
    response['matchedDN'] = LDAPDN('')
    response['diagnosticMessage'] = LDAPString('')
    referral = None
    server_sasl_credentials = None
    if referral:
        response['referral'] = Referral(referral)

    if server_sasl_credentials:
        response['serverSaslCreds'] = ServerSaslCreds(server_sasl_credentials)

    user.identity = dict_req['name']
    return response

@asyncio.coroutine
def do_unbind_operation(message_id, user):
    user.identity = 'unbound'
    pass


@asyncio.coroutine
def perform_request(writer, request, user):
    print('performing request', request)
    message_id = int(request.getComponentByName('messageID'))
    dict_req = decode_request(request)
    if dict_req['type'] == 'bindRequest':
        response = yield from do_bind_operation(message_id, dict_req, user)
        response_type = 'bindResponse'
    elif dict_req['type'] == 'unbindRequest':
        yield from do_unbind_operation(message_id, user)
        writer.close()
        return

    print('ID:', message_id, dict_req)
    ldap_message = LDAPMessage()
    ldap_message['messageID'] = MessageID(message_id)
    ldap_message['protocolOp'] = ProtocolOp().setComponentByName(response_type, response)
    controls = None
    message_controls = build_controls_list(controls)
    if message_controls is not None:
        ldap_message['controls'] = message_controls

    print('sending', ldap_message)
    encoded_message = encoder.encode(ldap_message)
    writer.write(encoded_message)
    writer.drain()


@asyncio.coroutine
def process_messages(writer, messages, user):
    print('received {} messages from {}'.format(len(messages), user.identity))
    for request in messages:
        while len(request) > 0:
            ldap_req, unprocessed = decoder.decode(request, asn1Spec=LDAPMessage())
            request = unprocessed
            asyncio.async(perform_request(writer, ldap_req, user))
    print('processed request')


def client_connected(reader, writer):
    user = User()
    task = asyncio.async(handle_client(reader, writer, user))
    print('new connection')
    clients[task] = (reader, writer, user)

    def client_done(task_done):
        print('closing connection')
        del clients[task_done]
        writer.close()

    task.add_done_callback(client_done)

@asyncio.coroutine
def handle_client(reader, writer, user):
    data = b'X'
    while data:
        messages = []
        receiving = True
        unprocessed = b''
        data = b''
        get_more_data = True
        while receiving:
            if get_more_data:
                data = yield from reader.read(4096)
                unprocessed += data
            if len(data) > 0:
                length = compute_ldap_message_size(unprocessed)
                if length == -1:  # too few data to decode message length
                    get_more_data = True
                    continue
                if len(unprocessed) < length:
                    get_more_data = True
                else:
                    messages.append(unprocessed[:length])
                    unprocessed = unprocessed[length:]
                    get_more_data = False
                    if len(unprocessed) == 0:
                        receiving = False
            else:
                receiving = False
        print('received {} bytes'.format(len(data)))

        if messages:
            yield from process_messages(writer, messages, user)
            yield from writer.drain()

    print('exit handle')
