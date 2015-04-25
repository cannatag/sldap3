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

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import SafeConfigParser as ConfigParser  # Python 2.6

from os.path import abspath, join, sep
from os import getcwd
from sys import platform

config_file_name = 'sldap3.conf'
config_file_path = sep + 'etc'
config = ConfigParser()
config_file = config.read([join(config_file_path, config_file_name), config_file_name])
nuovo_config = False

if not config_file:
    nuovo_config = True
    config.add_section('user_backend')
    config.set('user_backend', 'json', '/root/sldap3/test/localhost-users.json')
    config.add_section('logging')
    config.set('logging', 'file_name', 'C:\\Temp\\sldap3.log' if platform == 'win32' else '/var/log/sldap3')
    config.set('logging', 'formatter', '%%(asctime)s - %%(process)d - %%(threadName)s - %%(levelname)s - %%(name)s - %%(message)s')

    with open(config_file_name, 'wb') as config_file:
        config.write(config_file)

from .log import conf_logger
logger = conf_logger('sldap3.config')
logger.info('working directory: %s', getcwd())
if nuovo_config:
    logger.info('new configuration file: %s' % abspath(config_file.name))
else:
    logger.info('current configuration file: %s' % [abspath(filename) for filename in config_file])
