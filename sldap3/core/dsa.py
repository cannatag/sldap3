"""
"""

# Created on 2015.03.15
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
# along with sldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

import asyncio
import ssl

from ldap3 import SEQUENCE_TYPES, LDAPControlsError
from ldap3.core.exceptions import LDAPExceptionError
from ldap3.strategy.base import BaseStrategy
from ldap3.protocol.convert import build_controls_list
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

from ldap3.protocol.rfc4511 import LDAPMessage, MessageID, ProtocolOp, Controls, Control
from ldap3.protocol.rfc2696 import RealSearchControlValue
from ldap3.protocol.oid import Oids
from core.user import User
from operation.bind import do_bind_operation
from operation.unbind import do_unbind_operation


def client_connected(reader, writer):
    dsa = asyncio.get_event_loop()._dsa
    user = User()
    task = dsa.loop.create_task(dsa.handle_client(reader, writer, user))
    print('new connection on server', dsa.name)
    dsa.clients[task] = (reader, writer, user)

    def client_done(task_done):
        print('closing connection on server', dsa.name, 'for user', user.identity)
        del dsa.clients[task_done]
        writer.close()

    task.add_done_callback(client_done)


class Dsa(object):
    def __init__(self, name, address, port, use_ssl=False):
        self.name = name
        self.address = address
        self.port = port
        self.use_ssl = use_ssl
        self.clients = dict()
        self.server = None
        self.loop = None

    @asyncio.coroutine
    def status(self):
        last = None
        trigger = False
        while True:
            if len(self.clients) != last:
                print('Clients on server', self.name + ':', len(self.clients))
                last = len(self.clients)
            yield from asyncio.sleep(2)
            if self.clients:
                trigger = True
            if trigger and not self.clients:
                break
        print('Closing server', self.name)
        self.server.close()
        print('server {} closed'.format(self.name))

    def start(self):
        self.loop = asyncio.new_event_loop()
        self.loop._dsa = self
        asyncio.set_event_loop(self.loop)
        if self.use_ssl:
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ssl_context.options &= ~ssl.OP_NO_SSLv3
            coro = asyncio.start_server(client_connected, self.address, self.port, ssl=ssl_context)
        else:
            print('start_server', self.name)
            coro = asyncio.start_server(client_connected, self.address, self.port)
        self.server = self.loop.run_until_complete(coro)
        print('Server {} started'.format(self.name))
        self.loop.create_task(self.status())

        try:
            self.loop.run_until_complete(self.server.wait_closed())
        except KeyboardInterrupt:
            print('force exit server')
            self.server.close()
            print('server closed')
        finally:
            self.loop.close()
            print('loop closed')

    #@asyncio.coroutine
    def handle_client(self, reader, writer, user):
        data = -1 # enter loop
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
                    length = BaseStrategy.compute_ldap_message_size(unprocessed)
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
            print('received {} bytes for server {}'.format(len(data), self.name))
            if messages:
                for request in messages:
                    while len(request) > 0:
                        ldap_req, unprocessed = decoder.decode(request, asn1Spec=LDAPMessage())
                        request = unprocessed
                        self.loop.create_task(self.perform_request(writer, ldap_req, user))
                    print('processed request for server', self.name)
        print('exit handle for server', self.name)

    @asyncio.coroutine
    def perform_request(self, writer, request, user):
        print('performing request', request, 'on server', self.name)
        message_id = int(request.getComponentByName('messageID'))
        dict_req = BaseStrategy.decode_request(request)

        if dict_req['type'] == 'bindRequest':
            response = yield from do_bind_operation(self, user, message_id, dict_req)
            response_type = 'bindResponse'
        elif dict_req['type'] == 'unbindRequest':
            yield from do_unbind_operation(self, user, message_id)
            writer.close()
            return
        else:
            raise LDAPExceptionError('unknown operation')

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
