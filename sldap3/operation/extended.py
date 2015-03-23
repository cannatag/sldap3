"""
"""

# Created on 2015.03.22
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

# ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
#     requestName      [0] LDAPOID,
#     requestValue     [1] OCTET STRING OPTIONAL }

from ldap3 import RESULT_SUCCESS, RESULT_PROTOCOL_ERROR, RESULT_UNAVAILABLE
from protocol.rfc4511 import build_ldap_result, build_extended_response


@asyncio.coroutine
def do_extended_operation(dua, message_id, dict_req):
    print('do extended operation', dict_req)

    if dict_req['name'] == '1.3.6.1.4.1.1466.20037':  # start_tls
        if dua.dsa.secure_port:
            result = build_ldap_result(RESULT_SUCCESS)
        else:
            result = build_ldap_result(RESULT_UNAVAILABLE)
        response = build_extended_response(result, '1.3.6.1.4.1.1466.20037')
    else:
        result = build_ldap_result(RESULT_PROTOCOL_ERROR, diagnostic_message='extended operation not supported')

    return response, 'extendedResp'
