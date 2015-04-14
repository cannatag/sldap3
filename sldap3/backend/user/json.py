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


import json
from ..user import UserBaseBackend
from ...core.user import User


class JsonUserBackend(UserBaseBackend):
    def __init__(self, json_file):
        self.json_file = json_file
        try:
            self.users = json.load(open(json_file))
        except Exception:
            self.users = {}

        super().__init__()

    def find_user(self, identity):
        if identity in self.users:
            return User(identity, self.users[identity])

        return None

    def add_user(self, identity, authorization, credentials):
        if identity not in self.users:
            self.users[identity] = {'auth': authorization, 'password': credentials}
            return True

        return False

    def del_user(self, identity):
        if identity in self.users:
            del self.users[identity]
            return True

        return False

    def modify_user(self, identity, new_identity):
        if identity in self.users:
            if self.add_user(new_identity, self.users[identity]):
                self.del_user(identity)
                return True

        return False

    def check_credentials(self, user, credentials):
        if user.identity in self.users:
            if self.users[user.identity]['password'] == credentials:
                return True

        return False

    def store(self):
        json.dump({'users': self.users}, open(self.json_file, 'w+'))

    @classmethod
    def unauthenticated(cls):
        return User('un-authenticated')

    @classmethod
    def anonymous(cls):
        return User('anonymous')
