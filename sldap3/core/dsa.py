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
from ldap3 import RESULT_SUCCESS

from ldap3.core.exceptions import LDAPExceptionError
from ldap3.strategy.base import BaseStrategy
from ldap3.operation.bind import bind_request_to_dict
from ldap3.operation.add import add_request_to_dict
from ldap3.operation.compare import compare_request_to_dict
from ldap3.operation.delete import delete_request_to_dict
from ldap3.operation.extended import extended_request_to_dict
from ldap3.operation.modify import modify_request_to_dict
from ldap3.operation.modifyDn import modify_dn_request_to_dict
from ldap3.operation.search import search_request_to_dict
from pyasn1.codec.ber import decoder, encoder

from ldap3.protocol.rfc4511 import LDAPMessage
from ldap3.protocol.rfc2696 import RealSearchControlValue
from ldap3.protocol.oid import Oids
from .dua import Dua
from ..operation.bind import do_bind_operation
from operation.extended import do_extended_operation
from ..operation.unbind import do_unbind_operation
from protocol.rfc4511 import build_ldap_message


class Dsa(object):
    def __init__(self, name, address, port=389, secure_port=636, cert_file=None, key_file=None, key_file_password=None, user_backend=None):
        self.clients = dict()
        self.server = None
        self.secure_server = None
        self.loop = None
        self.name = name
        self.address = address
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.key_file_password = key_file_password
        self.user_backend = user_backend
        self.secure_port = secure_port if self.cert_file else None

    @asyncio.coroutine
    def status(self):
        last = None
        trigger = False
        while True:
            if len(self.clients) != last:
                print('Clients on DSA ', self.name + ':', len(self.clients))
                last = len(self.clients)
            yield from asyncio.sleep(2)
            if self.clients:
                trigger = True
            if trigger and not self.clients:
                break
        print('Closing DSA', self.name)
        self.stop()
        print('DSA {} closed'.format(self.name))

    def stop(self):
        if self.port:
            self.server.close()
        if self.secure_port:
            self.secure_server.close()

    def client_connected(self, reader, writer):
        dua = Dua(self.user_backend.anonymous(), reader, writer, self)
        self.register_client(dua)

    def start(self):
        self.loop = asyncio.new_event_loop()
        self.loop.private_dsa = self
        asyncio.set_event_loop(self.loop)

        if self.port:  # start unsecure server
            coro = asyncio.start_server(self.client_connected, self.address, self.port)
            self.server = self.loop.run_until_complete(coro)

        if self.secure_port:  # start secure server
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.cert_file, keyfile=self.key_file, password=self.key_file_password)
            secure_coro = asyncio.start_server(self.client_connected, self.address, self.secure_port, ssl=ssl_context)
            self.secure_server = self.loop.run_until_complete(secure_coro)

        print('DSA {} started'.format(self.name))
        self.loop.create_task(self.status())

        try:
            if self.port:
                self.loop.run_until_complete(self.server.wait_closed())
            if self.secure_port:
                self.loop.run_until_complete(self.secure_server.wait_closed())
        except KeyboardInterrupt:
            print('forced exit DSA')
            if self.port:
                self.server.close()
            if self.secure_port:
                self.secure_server.close()
            print('DSA closed')
        finally:
            self.loop.close()
            print('loop closed')

    @asyncio.coroutine
    def handle_client(self, dua):
        data = -1  # enter loop
        while data:
            messages = []
            receiving = True
            unprocessed = b''
            data = b''
            get_more_data = True
            while receiving:
                if get_more_data:
                    data = yield from dua.reader.read(4096)
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
                        self.loop.create_task(self.perform_request(dua, ldap_req))
                    print('processed request for server', self.name)
        print('exit handle for server', self.name)

    @asyncio.coroutine
    def perform_request(self, dua, request):
        message_id = int(request.getComponentByName('messageID'))
        dict_req = BaseStrategy.decode_request(request)
        if message_id not in dua.pending:
            dua.pending[message_id] = dict_req
            if dict_req['type'] == 'bindRequest':
                response, response_type = yield from do_bind_operation(dua, message_id, dict_req)
            elif dict_req['type'] == 'unbindRequest':
                yield from do_unbind_operation(dua, message_id)
                dua.writer.close()
                return
            elif dict_req['type'] == 'extendedReq':
                response, response_type = do_extended_operation(dua, message_id, dict_req)
                print(response)
                if response['responseName'] == '1.3.6.1.4.1.1466.20037' and response['result'] == RESULT_SUCCESS:  # issue start_tls
                    print('start_tls')
                    ldap_message = build_ldap_message(message_id, response_type, response, None)
                    dua.send(ldap_message)
                    dua.start_tls()
                response = None
            else:
                dua.abort(diagnostic_message='unknown operation')
                return

            del dua.pending[message_id]
            if not response:  # notice of disconnection sent while doing operation
                return
            print('ID:', message_id, dict_req)
            controls = None  # TODO
            ldap_message = build_ldap_message(message_id, response_type, response, controls)
        else:  # pending message with same id of previous message
            dua.abort(diagnostic_message='duplicate message ID')
            return
        dua.send(ldap_message)

    def register_client(self, dua):
        task = self.loop.create_task(self.handle_client(dua))
        print('new connection on server', self.name)
        self.clients[task] = dua

        def client_done(task_done):
            print('closing connection on server', self.name, 'for identity', dua.user.identity)
            self.unregister_client(task_done)
            dua.writer.close()

        task.add_done_callback(client_done)

    def unregister_client(self, task):
        del self.clients[task]
