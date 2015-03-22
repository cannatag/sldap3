"""
"""

# Created on 2015.03.18
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
from ldap3 import RESULT_INVALID_CREDENTIALS, RESULT_SUCCESS, RESULT_PROTOCOL_ERROR, RESULT_AUTH_METHOD_NOT_SUPPORTED
from ldap3.protocol.rfc4511 import ServerSaslCreds, BindResponse
from ..protocol.rfc4511 import build_ldap_result
from protocol.rfc4511 import build_bind_response

# BindRequest ::= [APPLICATION 0] SEQUENCE {
#     version                 INTEGER (1 ..  127),
#     name                    LDAPDN,
#     authentication          AuthenticationChoice }
#
# AuthenticationChoice ::= CHOICE {
#     simple                  [0] OCTET STRING,
#                             -- 1 and 2 reserved
#     sasl                    [3] SaslCredentials,
# ... }
#
# SaslCredentials ::= SEQUENCE {
#     mechanism               LDAPString,
#     credentials             OCTET STRING OPTIONAL }


@asyncio.coroutine
def do_bind_operation(dsa, user, message_id, dict_req):
    print('do bind operation', dict_req)
    server_sasl_credentials = None
    if dict_req['version'] != 3:  # protocol version check (RFC4511 4.2 - line 878)
        result = build_ldap_result(RESULT_PROTOCOL_ERROR, diagnostic_message='only LDAP version 3 protocol allowed')
        user = dsa.user_backend.anonymous()
    else:
        if dict_req['authentication']['simple'] == '' and not dict_req['name']:  # anonymous simple authentication (RFC4511 4.2 - line 883)
            user = dsa.user_backend.anonymous()
            result = build_ldap_result(RESULT_SUCCESS, diagnostic_message='anonymous authentication successful')
        elif dict_req['name'] and dict_req['authentication']['simple']:  # simple authentication (RFC4511 4.2 - line 888)
            user = dsa.user_backend.find_user(dict_req['name'])
            if user:
                if not dsa.user_backend.check_credentials(user, dict_req['authentication']['simple']):
                    yield from asyncio.sleep(3)  # pause if invalid user
                    result = build_ldap_result(RESULT_INVALID_CREDENTIALS, diagnostic_message='invalid credentials')
                    user = dsa.user_backend.anonymous()
                else:  # successful simple authentication
                    result = build_ldap_result(RESULT_SUCCESS, diagnostic_message='user authentication successful')
            else:
                yield from asyncio.sleep(3)  # pause if not existent user
                result = build_ldap_result(RESULT_INVALID_CREDENTIALS, diagnostic_message='user not found')
                user = dsa.user_backend.anonymous()
        elif dict_req['authentication']['sasl']:  # sasl authentication
            result = build_ldap_result(RESULT_AUTH_METHOD_NOT_SUPPORTED, diagnostic_message='SASL not available')
            user = dsa.user_backend.anonymous()
        else:  # undefined
            result = None

    response = build_bind_response(result, server_sasl_credentials)
    print(user.identity, response)
    return response
