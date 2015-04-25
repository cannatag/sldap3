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

import logging
from logging import FileHandler
from .config import config
_conf_logging_file_name = config.get('logging') if config.has_option('logging', 'file_name') else None
_conf_logging_formatter = config.get('logging', 'formatter') if config.has_option('logging', 'formatter') else '%(asctime)s - %(levelname)s - %(name)s - %(message)s'

emulate_null_handler = False

if 'NullHandler' not in dir(logging):
    emulate_null_handler = True

    class NullHandler(logging.Handler):
        def emit(self, record):
            pass
else:
    NullHandler = logging.NullHandler


def conf_logger(logger_name):
    level = config.get('log', logger_name).lower() if config.has_option('log', logger_name) else 'info'
    new_logger = logging.getLogger(logger_name)
    if _conf_logging_file_name:
        handler = FileHandler(_conf_logging_file_name, mode='a', encoding='utf-8')
    else:
        handler = NullHandler()

    if level == 'debug':
        new_logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    elif level == 'info':
        new_logger.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)
    elif level == 'warn':
        new_logger.setLevel(logging.WARN)
        handler.setLevel(logging.WARN)
    elif level == 'error':
        new_logger.setLevel(logging.ERROR)
        handler.setLevel(logging.ERROR)
    elif level == 'critical':
        new_logger.setLevel(logging.CRITICAL)
        handler.setLevel(logging.CRITICAL)

    handler.setFormatter(logging.Formatter(_conf_logging_formatter))
    new_logger.addHandler(handler)

    return new_logger

logger = conf_logger('sldap3.util.log')
logger.debug('conf: logging.file_name: %s' % _conf_logging_file_name)
logger.debug('conf: logging.formatter: %s' % _conf_logging_formatter)
logger.info('conf: emulate NullHandler: %s', emulate_null_handler)
