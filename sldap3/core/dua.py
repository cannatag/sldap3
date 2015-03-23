"""
"""

# Created on 2015.03.13
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
from datetime import datetime
from ldap3 import RESULT_PROTOCOL_ERROR
from pyasn1.codec.ber import decoder, encoder
from protocol.rfc4511 import build_extended_response, build_ldap_result, build_ldap_message
import ssl


class Dua(object):
    """
    Directory User Agent - a client actually connected to the DSA with an active transport
    """
    def __init__(self, user, reader, writer, dsa):
        self.user = user
        self.dsa = dsa
        self.connected_time = datetime.now()
        self.reader = reader
        self.writer = writer
        self.tls_started = False
        self.pending = {}

    def send(self, ldap_message):
        encoded_message = encoder.encode(ldap_message)
        self.writer.write(encoded_message)
        self.writer.drain()

    def abort(self, result_code=RESULT_PROTOCOL_ERROR, diagnostic_message=''):  # unsolicited notification of disconnection
        result = build_ldap_result(result_code, diagnostic_message=diagnostic_message)
        response = build_extended_response(result, '1.3.6.1.4.1.1466.20036')
        ldap_message = build_ldap_message(0, 'extendedResp', response)
        self.send(ldap_message)
        self.writer.close()

    def start_tls(self):
        if not self.tls_started:
            print('start_tls')
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.dsa.cert_file, keyfile=self.dsa.key_file, password=self.dsa.key_file_password)
            wrapped_socket = ssl_context.wrap_socket(self.writer.get_extra_info('socket'), server_side=True, do_handshake_on_connect=True)
            return True

        return False
