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

try:
    from win32api import GetTempPath
except ImportError:
    def GetTempPath():
        return join('C:', sep, 'Temp')

from os.path import abspath, join, sep
from os import getcwd
import platform


config_file_name = 'sldap3.conf'
if platform.system() == 'Windows':
    temp_path = GetTempPath()
    log_path = temp_path
    config_file_path = temp_path
else:
    temp_path = join(sep, 'tmp')
    log_path = join(sep, 'var', 'log')
    config_file_path = join(sep, 'etc')

config = ConfigParser()
config_file = config.read([join(config_file_path, config_file_name), config_file_name])  # search full path or working directory
if not config_file:
    config.add_section('user_backend')
    config.set('user_backend', 'json', join(temp_path, 'sldap3-users.json'))
    config.add_section('logging')
    config.set('logging', 'file_name', join(log_path, 'sldap3.log'))
    config.set('logging', 'formatter', '%%(asctime)s - %%(process)d - %%(threadName)s - %%(levelname)s - %%(name)s - %%(message)s')
    config.set('logging', 'sldap3.config', 'debug')
    config.set('logging', 'sldap3.logging', 'debug')
    config.set('logging', 'sldap3.daemonize', 'debug')
    config.set('logging', 'sldap3.dsa', 'debug')
    config.set('logging', 'sldap3.dua', 'debug')
    config.set('logging', 'sldap3.instance', 'debug')
    config.set('logging', 'sldap3.operation.bind', 'debug')
    config.set('logging', 'sldap3.operation.unbind', 'debug')
    config.set('logging', 'sldap3.operation.extended', 'debug')

    with open(join(config_file_path, config_file_name), 'w') as new_config_file:
        config.write(new_config_file)

# from .log import conf_logger
# logger = conf_logger('sldap3.config')
# logger.info('working directory: %s', getcwd())
# if nuovo_config:
#     logger.info('new configuration file: %s' % abspath(config_file.name))
# else:
#     logger.info('current configuration file: %s' % [abspath(filename) for filename in config_file])

