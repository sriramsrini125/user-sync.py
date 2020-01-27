# Copyright (c) 2016-2017 Adobe Inc.  All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import user_sync.error
import logging
import os
import sys
import click
import shutil
from click_default_group import DefaultGroup
from datetime import datetime
from operator import itemgetter

import six
import yaml

import user_sync.config
import user_sync.connector.directory
import user_sync.connector.umapi
import user_sync.helper
import user_sync.lockfile
import user_sync.rules
import user_sync.cli
import user_sync.resource
from user_sync.error import AssertionException
from user_sync.version import __version__ as app_version
from user_sync.config import ConfigLoader

class DirectoryConnectorManager(object):
    def __init__(self, config_loader):
        self.config_loader = config_loader

        for parameter_name, parameter_value in six.iteritems(self.config_loader.get_invocation_options()):
            if (parameter_name=='connector'):
                connectortype=parameter_value
                print('connector type is ', connectortype)
        self.connectors = [self.build_connector(c) for c in self.get_connector_list(connectortype)]
        #self.connectors = self.build_connector(self, config_loader)

    def get_connector_list(self, connectortype):
        connector_list = self.config_loader.get_directory_connector_configs(connectortype)
        print ('connector list ', connector_list)
        return connector_list



    def get_connector_options(self, config):
        directory_connector_options = self.config_loader.get_directory_connector_options(config['path'])
        return directory_connector_options


    def initialize(self, options=None):
        """
        :type options: dict
        """
        if options is None:
            options = {}
        self.state = self.implementation.connector_initialize(options)

    def build_connector(self, config):
        print('connector called')
        rule_config = self.config_loader.get_rule_options()
        directory_connector_module_name = 'user_sync.connector.directory_' + config['type']
        if directory_connector_module_name is not None:
            directory_connector_module = __import__(directory_connector_module_name, fromlist=[''])
            directory_connector = user_sync.connector.directory.DirectoryConnector(directory_connector_module)
            directory_connector_options = self.get_connector_options(config)
            #self.config_loader.check_unused_config_keys()

        if directory_connector is not None and directory_connector_options is not None:
            # specify the default user_identity_type if it's not already specified in the options
            if 'user_identity_type' not in directory_connector_options:
                directory_connector_options['user_identity_type'] = rule_config['new_account_type']
                directory_connector.initialize(directory_connector_options)

        additional_group_filters =   None
        additional_groups = rule_config.get('additional_groups', None)
        if additional_groups and isinstance(additional_groups, list):
            additional_group_filters = [r['source'] for r in additional_groups]
        if directory_connector is not None:
            directory_connector.state.additional_group_filters = additional_group_filters

        return directory_connector

    def load_users_and_groups(self, groups, extended_attributes, all_users):
        # full process flow starts here
        users = {}
        for c in self.connectors:
            print('final loop called')
            users.update(c.load_users_and_groups(groups, extended_attributes, all_users))
            #users = self.load_users_and_groups_sub(groups, extended_attributes, all_users)
        return users

