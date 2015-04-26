#!/usr/bin/env python

"""
"""

# Created on 2015.04.20
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

import sys
from sldap3 import EXEC_THREAD
from sldap3.utils.config import config
from sldap3.utils.log import conf_logger

logger = conf_logger('sldap3.daemonize')

try:
    import resource
except ImportError:
    logger.error('deamons are available on Linux only')
    sys.exit(5)

try:
    from pep3143daemon import DaemonContext, PidFile
except ImportError:
    logger.error('pep3143daemon package missing')
    sys.exit(6)

try:
    import pyasn1
except ImportError:
    logger.error('pyasn1 package missing')
    sys.exit(2)

try:
    import ldap3
except ImportError:
    logger.error('ldap3 package missing')
    sys.exit(3)

try:
    from trololio import ASYNCIO, TROLLIUS
except ImportError:
    logger.error('trollius or trololio package missing')
    sys.exit(4)

try:
    import sldap3
except ImportError:
    logger.error('sldap3 package missing')
    sys.exit(5)


class Sldap3Daemon(DaemonContext):
    def run(self):
        if ASYNCIO:
            logger.info('using asyncio from standard library')
        elif TROLLIUS:
            logger.info('using trollius external package')

        logger.info('instantiating sldap3 daemon')
        self.instances = []
        user_backend = sldap3.JsonUserBackend('/tmp/sldap3-users.json')
        user_backend.add_user('giovanni', 'admin', 'password')
        user_backend.add_user('beatrice', 'user', 'password')
        user_backend.store()

        dsa1 = sldap3.Instance(
            sldap3.Dsa('DSA1',
                       '0.0.0.0',
                       cert_file='/root/sldap3/test/server-cert.pem',
                       key_file='/root/sldap3/test/server-key.pem',
                       user_backend=user_backend),
            name='MixedInstance',
            executor=EXEC_THREAD)
        dsa2 = sldap3.Instance(
            sldap3.Dsa('DSA2',
                       '0.0.0.0',
                       port=1389,
                       user_backend=user_backend),
            name='UnsecureInstance',
            executor=EXEC_THREAD)

        self.instances.append(dsa1)
        self.instances.append(dsa2)

        for instance in self.instances:  # start each instance in a new thread
            instance.start()

        logger.info('sldap3 daemon instantiation complete')

    def terminate(self, signal_number, stack_frame):
        logger.info('terminating sldap3 daemon')
        for instance in self.instances:  # wait for all instances to end
            instance.stop()
        logger.info('daemon sldap3 terminated')

if __name__ == '__main__':
    pid = '/tmp/sldap3.pid'
    pidfile = PidFile(pid)
    daemon = Sldap3Daemon(pidfile=pidfile)
    daemon.files_preserve = [handler.stream for handler in logger.handlers]  # preserve log file
    logger.debug('preserving files %s' % str(daemon.files_preserve))
    logger.info('daemonizing sldap3')
    daemon.open()
    logger.info('sldap3 demonized')
    daemon.run()
    logger.info('sldap3 daemon started')
