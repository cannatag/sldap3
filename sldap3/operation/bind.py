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
from ldap3.protocol.rfc4511 import ResultCode, LDAPDN, BindResponse, LDAPString, Referral, ServerSaslCreds

@asyncio.coroutine
def do_bind_operation(dsa, user, message_id, dict_req):
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