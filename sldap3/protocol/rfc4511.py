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

from ldap3.protocol.rfc4511 import LDAPResult, LDAPMessage, ProtocolOp, MessageID, Referral, BindResponse, \
    ServerSaslCreds, ExtendedResponse
from ldap3.protocol.convert import build_controls_list


def build_ldap_message(message_id, response_type, response, controls=None):
    # LDAPMessage ::= SEQUENCE {
    # messageID       MessageID,
    #     protocolOp      CHOICE {
    #         bindRequest           BindRequest,
    #         bindResponse          BindResponse,
    #         unbindRequest         UnbindRequest,
    #         searchRequest         SearchRequest,
    #         searchResEntry        SearchResultEntry,
    #         searchResDone         SearchResultDone,
    #         searchResRef          SearchResultReference,
    #         modifyRequest         ModifyRequest,
    #         modifyResponse        ModifyResponse,
    #         addRequest            AddRequest,
    #         addResponse           AddResponse,
    #         delRequest            DelRequest,
    #         delResponse           DelResponse,
    #         modDNRequest          ModifyDNRequest,
    #         modDNResponse         ModifyDNResponse,
    #         compareRequest        CompareRequest,
    #         compareResponse       CompareResponse,
    #         abandonRequest        AbandonRequest,
    #         extendedReq           ExtendedRequest,
    #         extendedResp          ExtendedResponse,
    #         ...,
    #         intermediateResponse  IntermediateResponse },
    #     controls       [0] Controls OPTIONAL }

    ldap_message = LDAPMessage()
    ldap_message['messageID'] = MessageID(message_id)
    ldap_message['protocolOp'] = ProtocolOp().setComponentByName(response_type, response)
    message_controls = build_controls_list(controls)
    if message_controls is not None:
        ldap_message['controls'] = message_controls

    return ldap_message


def build_ldap_result(result_code, matched_dn='', diagnostic_message='', referral=None):
    # LDAPResult ::= SEQUENCE {
    #     resultCode         ENUMERATED {
    #         success                      (0),
    #         operationsError              (1),
    #         protocolError                (2),
    #         timeLimitExceeded            (3),
    #         sizeLimitExceeded            (4),
    #         compareFalse                 (5),
    #         compareTrue                  (6),
    #         authMethodNotSupported       (7),
    #         strongerAuthRequired         (8),
    #              -- 9 reserved --
    #         referral                     (10),
    #         adminLimitExceeded           (11),
    #         unavailableCriticalExtension (12),
    #         confidentialityRequired      (13),
    #         saslBindInProgress           (14),
    #         noSuchAttribute              (16),
    #         undefinedAttributeType       (17),
    #         inappropriateMatching        (18),
    #         constraintViolation          (19),
    #         attributeOrValueExists       (20),
    #         invalidAttributeSyntax       (21),
    #              -- 22-31 unused --
    #         noSuchObject                 (32),
    #         aliasProblem                 (33),
    #         invalidDNSyntax              (34),
    #              -- 35 reserved for undefined isLeaf --
    #         aliasDereferencingProblem    (36),
    #              -- 37-47 unused --
    #         inappropriateAuthentication  (48),
    #         invalidCredentials           (49),
    #         insufficientAccessRights     (50),
    #         busy                         (51),
    #         unavailable                  (52),
    #         unwillingToPerform           (53),
    #         loopDetect                   (54),
    #              -- 55-63 unused --
    #         namingViolation              (64),
    #         objectClassViolation         (65),
    #         notAllowedOnNonLeaf          (66),
    #         notAllowedOnRDN              (67),
    #         entryAlreadyExists           (68),
    #         objectClassModsProhibited    (69),
    #              -- 70 reserved for CLDAP --
    #         affectsMultipleDSAs          (71),
    #              -- 72-79 unused --
    #         other                        (80),
    #         ...  },
    #     matchedDN          LDAPDN,
    #     diagnosticMessage  LDAPString,
    #     referral           [3] Referral OPTIONAL }

    ldap_result = LDAPResult()
    ldap_result['resultCode'] = result_code
    ldap_result['matchedDN'] = matched_dn
    ldap_result['diagnosticMessage'] = diagnostic_message
    if referral:
        ldap_result['referral'] = Referral(referral)
    return ldap_result


def build_bind_response(ldap_result, server_sasl_credentials):
    # BindResponse ::= [APPLICATION 1] SEQUENCE {
    #     COMPONENTS OF LDAPResult,
    #     serverSaslCreds    [7] OCTET STRING OPTIONAL }

    response = BindResponse()
    response['resultCode'] = ldap_result['resultCode']
    response['matchedDN'] = ldap_result['matchedDN']
    response['diagnosticMessage'] = ldap_result['diagnosticMessage']
    if ldap_result['referral']:
        response['referral'] = ldap_result['referral']
    if server_sasl_credentials:
        response['serverSaslCreds'] = ServerSaslCreds(server_sasl_credentials)

    return response


def build_extended_response(ldap_result, response_name=None, response_value=None):
    # ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
    #     COMPONENTS OF LDAPResult,
    #     responseName     [10] LDAPOID OPTIONAL,
    #     responseValue    [11] OCTET STRING OPTIONAL }
    response = ExtendedResponse()
    response['resultCode'] = ldap_result['resultCode']
    response['matchedDN'] = ldap_result['matchedDN']
    response['diagnosticMessage'] = ldap_result['diagnosticMessage']
    if response_name:
        response['responseName'] = response_name
    if response_value:
        response['responseValue'] = response_value

    return response
