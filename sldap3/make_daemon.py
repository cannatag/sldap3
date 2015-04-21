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

import logging
# from multiprocessing import Process
from threading import Thread
from time import sleep
import sys

logging.basicConfig(
    filename='/var/log/sldap3.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)-7.7s - %(message)s'
)

try:
    import resource
except ImportError:
    logging.error('deamons are available only on Linux')
    sys.exit(5)

try:
    from pep3143daemon import DaemonContext, PidFile
except ImportError:
    logging.error('pep3143daemon package missing')
    sys.exit(6)

try:
    import pyasn1
except ImportError:
    logging.error('pyasn1 package missing')
    sys.exit(2)

try:
    import ldap3
except ImportError:
    logging.error('ldap3 package missing')
    sys.exit(3)

try:
    from asyncio import BaseEventLoop
except ImportError:
    try:
        import trollius as asyncio
    except:
        logging.error('trollius package missing')
        sys.exit(4)

try:
    import sldap3
except ImportError:
    logging.error('sldap3 package missing')
    sys.exit(5)


def run():
    instances = []
    logging.info('Executing service...')
    user_backend = sldap3.JsonUserBackend('localhost-users.json')
    user_backend.add_user('giovanni', 'admin', 'password')
    user_backend.add_user('beatrice', 'user', 'password')
    user_backend.store()

    dsa1 = sldap3.Instance(
        sldap3.Dsa('DSA1', '0.0.0.0', cert_file='C:\\Temp\\server-cert.pem', key_file='C:\\Temp\\server-key.pem',
                   user_backend=user_backend))
    dsa2 = sldap3.Instance(sldap3.Dsa('DSA2', '0.0.0.0', port=1389, user_backend=user_backend))

    instances.append(dsa1)
    instances.append(dsa2)

    for instance in instances:  # start each instance in a new thread
        instance.executor = Thread(target=instance.dsa.start)
        instance.executor.start()

    # while not stop_requested:  # wait for stop signal
    # sleep(5)

    for instance in instances:  # wait for all instances to end
        instance.stop()

    logging.info('Service stopped')


if __name__ == '__main__':
    pid = '/tmp/sldap3.pid'
    pidfile = PidFile(pid)
    daemon = DaemonContext(pidfile=pidfile)

    logging.info('Demonizing')

    # daemon.open()
    logging.info('Demonized')
    run()
    logging.info('Done')
