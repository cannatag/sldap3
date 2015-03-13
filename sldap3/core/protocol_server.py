"""
"""

# Created on 2015.03.10
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

clients = []

@asyncio.coroutine
def send_data(transport, data_input):
    print('send_data')
    data_output = data_input[::-1]
    transport.write('XXX')
    yield


class Ldap3Protocol(asyncio.Protocol):
    def connection_made(self, transport):
        """
        Called when a connection is made.
        The argument is the transport representing the pipe connection.
        To receive data, wait for data_received() calls.
        When the connection is closed, connection_lost() is called.
        """
        print("Connection received!")
        self.transport = transport
        clients.append(self)

    @asyncio.coroutine
    def data_received(self, data):
        """
        Called when some data is received.
        The argument is a bytes object.
        """
        print('received data')
        yield from send_data(self.transport, data)
        print('yielded')

    def connection_lost(self, exc):
        """
        Called when the connection is lost or closed.
        The argument is an exception object or None (the latter
        meaning a regular EOF is received or the connection was
        aborted or closed).
        """
        print("Connection lost!")
        self.transport = None
        clients.remove(self)
