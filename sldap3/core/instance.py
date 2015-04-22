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

# from threading import Thread
# from multiprocessing import Process
import logging
from .. import EXEC_PROCESS, EXEC_THREAD

from .. import NATIVE_ASYNCIO
from time import sleep

if NATIVE_ASYNCIO:
    import asyncio
else:
    import trollius as asyncio
    from trollius import From, Return


class Instance(object):
    def __init__(self, dsa, name=None, executor=EXEC_THREAD):
        self.dsa = dsa
        self.dsa.instance = self
        self.loop = None
        self.name = self.dsa.name if not name else name
        if executor == EXEC_THREAD:
            from threading import Thread
            self.executor = Thread(target=self.dsa.start)
        elif executor == EXEC_PROCESS:
            from multiprocessing import Process
            self.executor = Process(target=self.dsa.start)
        else:
            raise Exception('unknown executor')

        self.started = False

    def start(self):
        if not self.started:
            logging.info('starting instance %s' % self.name)
            self.executor.start()
            self.started = True

    def stop(self):
        if self.started:
            logging.info('stopping instance %s' % self.name)
            self.dsa.stop()
            logging.debug('stopping loop for instance %s' % self.name)
            self.loop.call_soon_threadsafe(self.loop.stop)
            logging.debug('closing loop for instance %s' % self.name)
            while self.loop.is_running():
                logging.debug('waiting for Instance %s loop to stop' % self.name)
                sleep(0.2)
            self.loop.call_soon_threadsafe(self.loop.close)
            logging.info('Instance %s loop halted and closed' % self.name)
            logging.debug('waiting for instance %s executor to join' % self.name)
            self.executor.join()
            logging.debug('instance %s joined' % self.name)
            self.started = False
            logging.info('stopped instance %s' % self.name)
