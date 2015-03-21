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
from ldap3.protocol.rfc4511 import ResultCode, LDAPDN, BindResponse, LDAPString, Referral, ServerSaslCreds

@asyncio.coroutine
def do_bind_operation(dsa, user, message_id, dict_req):
    print('do bind operation', dict_req)
    server_sasl_credentials = None
    response = BindResponse()
    if dict_req['version'] != 3:  # protocol version check (RFC4511 4.2 - line 878)
        response['resultCode'] = ResultCode(RESULT_PROTOCOL_ERROR)
        response['matchedDN'] = LDAPDN('')
        response['diagnosticMessage'] = LDAPString('only LDAP version 3 protocol allowed')
        user = dsa.user_backend.unauthenticated()
    else:
        if dict_req['authentication']['simple'] == '' and not dict_req['name']:  # anonymous authentication (RFC4511 4.2 - line 883)
            user = dsa.user_backend.anonymous()
            response['resultCode'] = ResultCode(RESULT_SUCCESS)
            response['matchedDN'] = LDAPDN('')
            response['diagnosticMessage'] = LDAPString('anonymous authentication successful')
        else:
            if dict_req['name'] and dict_req['authentication']['simple']:  # simple authentication (RFC4511 4.2 - line 888)
                user = dsa.user_backend.find_user(dict_req['name'])
                if user:
                    if not dsa.user_backend.check_credentials(user, dict_req['authentication']['simple']):
                        yield from asyncio.sleep(3)  # pause if invalid user
                        response['resultCode'] = ResultCode(RESULT_INVALID_CREDENTIALS)
                        response['matchedDN'] = LDAPDN('')
                        response['diagnosticMessage'] = LDAPString('invalid credentials')
                        user = dsa.user_backend.unauthenticated()
                    else:  # successful simple authentication
                        response['resultCode'] = ResultCode(RESULT_SUCCESS)
                        response['matchedDN'] = LDAPDN('')
                        response['diagnosticMessage'] = LDAPString('user authentication successful')
                else:
                    yield from asyncio.sleep(3)  # pause if not existent user
                    response['resultCode'] = ResultCode(RESULT_INVALID_CREDENTIALS)
                    response['matchedDN'] = LDAPDN('')
                    response['diagnosticMessage'] = LDAPString('user not found')
                    user = dsa.user_backend.unauthenticated()
            elif dict_req['authentication']['sasl']:  # sasl authentication
                response['resultCode'] = ResultCode(RESULT_AUTH_METHOD_NOT_SUPPORTED)
                response['matchedDN'] = LDAPDN('')
                response['diagnosticMessage'] = LDAPString('sasl not available')

    referral = None
    if referral:
        response['referral'] = Referral(referral)

    if server_sasl_credentials:
        response['serverSaslCreds'] = ServerSaslCreds(server_sasl_credentials)

    print(user.identity, response)
    return response
