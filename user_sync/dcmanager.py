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

import user_sync.cli
import user_sync.config
import user_sync.connector.directory
import user_sync.connector.umapi
import user_sync.error
import user_sync.helper
import user_sync.lockfile
import user_sync.resource
import user_sync.rules


class DirectoryConnectorManager(object):
    def __init__(self, config_loader, additional_groups, default_account_type):
        self.config_loader = config_loader
        self.additional_groups = additional_groups
        self.new_account_type = default_account_type
        self.conn_cfg = config_loader.get_directory_connector_configs()
        self.connectors = {c['id']: self.build_connector(c) for c in self.conn_cfg}

        print()
    def build_connector(self, config):

        directory_connector = None
        directory_connector_options = None
        directory_connector_module_name = self.config_loader.get_directory_connector_module_name(config['type'])
        if directory_connector_module_name is not None:
            directory_connector_module = __import__(directory_connector_module_name, fromlist=[''])
            directory_connector = user_sync.connector.directory.DirectoryConnector(directory_connector_module)
            directory_connector_options = self.config_loader.get_directory_connector_options(config['path'])

        if directory_connector is not None and directory_connector_options is not None:
            # specify the default user_identity_type if it's not already specified in the options
            if 'user_identity_type' not in directory_connector_options:
                directory_connector_options['user_identity_type'] = self.new_account_type
                directory_connector.initialize(directory_connector_options)

        additional_group_filters = None
        if self.additional_groups and isinstance(self.additional_groups, list):
            additional_group_filters = [r['source'] for r in self.additional_groups]
        if directory_connector is not None:
            directory_connector.state.additional_group_filters = additional_group_filters

        return directory_connector

    def load_users_and_groups(self, groups, extended_attributes, all_users):
        # full process flow starts here
        users = {}
        for c in self.connectors:
            print('final loop called')
            users.update(c.load_users_and_groups(groups, extended_attributes, all_users))
            # users = self.load_users_and_groups_sub(groups, extended_attributes, all_users)
        return users
