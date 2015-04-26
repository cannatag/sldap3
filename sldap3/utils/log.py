"""
"""

# Created on 2015.04.25
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

from logging import FileHandler, getLogger, DEBUG, INFO, WARN, ERROR, CRITICAL, Formatter
from .config import config

_conf_logging_file_name = config.get('logging', 'file_name') if config.has_option('logging', 'file_name') else None
_conf_logging_formatter = config.get('logging', 'formatter') if config.has_option('logging', 'formatter') else '%(asctime)s - %(levelname)s - %(name)s - %(message)s'

emulate_null_handler = False

try:
    from logging import NullHandler
except ImportError:  # NullHandler not present in Python < 2.7
    emulate_null_handler = True
    from logging import Handler

    class NullHandler(Handler):
        def emit(self, record):
            pass

if _conf_logging_file_name:
    handler = FileHandler(_conf_logging_file_name, mode='a', encoding='utf-8')
else:
    handler = NullHandler()


def conf_logger(logger_name):
    level = config.get('logging', logger_name).lower() if config.has_option('logging', logger_name) else 'info'
    new_logger = getLogger(logger_name)
    if level == 'debug':
        new_logger.setLevel(DEBUG)
        handler.setLevel(DEBUG)
    elif level == 'info':
        new_logger.setLevel(INFO)
        handler.setLevel(INFO)
    elif level == 'warn' or level == 'warning':
        new_logger.setLevel(WARN)
        handler.setLevel(WARN)
    elif level == 'error':
        new_logger.setLevel(ERROR)
        handler.setLevel(ERROR)
    elif level == 'critical':
        new_logger.setLevel(CRITICAL)
        handler.setLevel(CRITICAL)

    handler.setFormatter(Formatter(_conf_logging_formatter))
    new_logger.addHandler(handler)

    return new_logger

logger = conf_logger('sldap3.logging')
logger.info('file_name: %s' % _conf_logging_file_name)
logger.debug('formatter: %s' % _conf_logging_formatter)
logger.debug('emulated NullHandler: %s', emulate_null_handler)
