import os
import shutil

import pytest
import six
import yaml

from tests.util import make_dict, merge_dict
from user_sync.config import ConfigFileLoader, ConfigLoader, DictConfig
from user_sync.error import AssertionException


@pytest.fixture
def config_files(fixture_dir, tmpdir):
    config_files = {
        'ldap': 'connector-ldap.yml',
        'umapi': 'connector-umapi.yml',
        'root_config': 'user-sync-config.yml',
        'extension': 'extension-config.yml',
    }

    for k, n in six.iteritems(config_files):
        shutil.copy(os.path.join(fixture_dir, n), tmpdir.dirname)
        config_files[k] = os.path.join(tmpdir.dirname, n)
    return config_files


@pytest.fixture
def modify_config(config_files):
    def _modify_config(name, key, value):
        path = config_files[name]
        conf = yaml.safe_load(open(path))
        merge_dict(conf, make_dict(key, value))
        yaml.dump(conf, open(path, 'w'))
        return path

    return _modify_config


# A shortcut for root
@pytest.fixture
def modify_root_config(modify_config):
    def _modify_root_config(key, value):
        return modify_config('root_config', key, value)

    return _modify_root_config


def load_ldap_config_options(args):
    from user_sync.connector.directory import DirectoryConnector
    from user_sync.connector.directory_ldap import LDAPDirectoryConnector

    config_loader = ConfigLoader(args)
    dc_mod_name = config_loader.get_directory_connector_module_name()
    dc_mod = __import__(dc_mod_name, fromlist=[''])
    dc = DirectoryConnector(dc_mod)
    dc_config_options = config_loader.get_directory_connector_options(dc.name)
    caller_config = DictConfig('%s configuration' % dc.name, dc_config_options)
    return LDAPDirectoryConnector.get_options(caller_config)


def test_load_root(config_files):
    """Load root config file and test for presence of root-level keys"""
    config = ConfigFileLoader.load_root_config(config_files['root_config'])
    assert isinstance(config, dict)
    assert ('adobe_users' in config and 'directory_users' in config and
            'logging' in config and 'limits' in config and
            'invocation_defaults' in config)


def test_max_adobe_percentage(cli_args, modify_root_config):
    root_config_file = modify_root_config(['limits', 'max_adobe_only_users'], "50%")
    config = ConfigFileLoader.load_root_config(root_config_file)
    assert ('limits' in config and 'max_adobe_only_users' in config['limits'] and
            config['limits']['max_adobe_only_users'] == "50%")

    args = cli_args({'config_filename': root_config_file})
    options = ConfigLoader(args).get_rule_options()
    assert 'max_adobe_only_users' in options and options['max_adobe_only_users'] == '50%'

    modify_root_config(['limits', 'max_adobe_only_users'], "error%")
    with pytest.raises(AssertionException):
        ConfigLoader(args).get_rule_options()


def test_additional_groups_config(cli_args, modify_root_config):
    addl_groups = [
        {
            "source": r"ACL-(.+)",
            "target": r"ACL-Grp-(\1)"},
        {
            "source": r"(.+)-ACL",
            "target": r"ACL-Grp-(\1)"},
    ]
    root_config_file = modify_root_config(['directory_users', 'additional_groups'], addl_groups)
    config = ConfigFileLoader.load_root_config(root_config_file)
    assert ('additional_groups' in config['directory_users'] and
            len(config['directory_users']['additional_groups']) == 2)

    args = cli_args({'config_filename': root_config_file})
    options = ConfigLoader(args).get_rule_options()
    assert addl_groups[0]['source'] in options['additional_groups'][0]['source'].pattern
    assert addl_groups[1]['source'] in options['additional_groups'][1]['source'].pattern


def test_twostep_config(cli_args, config_files, modify_config):
    modify_config('ldap', ['two_steps_lookup'], {})
    args = cli_args({'config_filename': config_files['root_config']})

    # test invalid "two_steps_lookup" config
    with pytest.raises(AssertionException):
        load_ldap_config_options(args)

    # test valid "two_steps_lookup" config with "group_member_filter_format" still set
    modify_config('ldap', ['two_steps_lookup', 'group_member_attribute_name'], 'member')
    with pytest.raises(AssertionException):
        load_ldap_config_options(args)

    # test valid "two_steps_lookup" setup
    modify_config('ldap', ['two_steps_lookup', 'group_member_attribute_name'], 'member')
    modify_config('ldap', ['group_member_filter_format'], "")
    options = load_ldap_config_options(args)
    assert 'two_steps_enabled' in options
    assert 'two_steps_lookup' in options
    assert 'group_member_attribute_name' in options['two_steps_lookup']
    assert options['two_steps_lookup']['group_member_attribute_name'] == 'member'


def test_adobe_users_config(cli_args, config_files, modify_root_config):
    args = cli_args({
        'config_filename': config_files['root_config']})

    # test default
    config_loader = ConfigLoader(args)
    options = config_loader.load_invocation_options()
    assert 'adobe_users' in options
    assert options['adobe_users'] == ['all']

    # test default invocation
    modify_root_config(['invocation_defaults', 'adobe_users'], "mapped")
    config_loader = ConfigLoader(args)
    options = config_loader.load_invocation_options()
    assert 'adobe_users' in options
    assert options['adobe_users'] == ['mapped']

    # test command line param
    modify_root_config(['invocation_defaults', 'adobe_users'], "all")
    args = cli_args({'config_filename': config_files['root_config'], 'adobe_users': ['mapped']})
    config_loader = ConfigLoader(args)
    options = config_loader.load_invocation_options()
    assert 'adobe_users' in options
    assert options['adobe_users'] == ['mapped']


def test_get_umapi_options(cli_args, config_files, modify_root_config):
    root_config = config_files['root_config']
    umapi_config = config_files['umapi']

    tmp_folder = os.path.dirname(root_config)
    with open(os.path.join(tmp_folder, 'private.key'), 'w') as key:
        key.write("data")

    # tests a single primary umapi configration
    args = cli_args({'config_filename': root_config})
    config_loader = ConfigLoader(args)
    primary, secondary = config_loader.get_umapi_options()
    assert {'server', 'enterprise'} <= set(primary)
    assert secondary == {}

    # tests secondary connector
    modify_root_config(['adobe_users', 'connectors', 'umapi'],
                       [umapi_config, {'secondary_console': umapi_config}])

    config_loader = ConfigLoader(args)
    primary, secondary = config_loader.get_umapi_options()
    assert {'server', 'enterprise'} <= set(primary)
    assert 'secondary_console' in secondary

    # tests secondary umapi configuration assertion
    modify_root_config(['adobe_users', 'connectors', 'umapi'],
                       [{'primary': umapi_config}, umapi_config])

    config_loader = ConfigLoader(args)
    with pytest.raises(AssertionException) as error:
        config_loader.get_umapi_options()
    assert "Secondary umapi configuration found with no prefix:" in str(error.value)

    # tests v1 assertion
    modify_root_config(['dashboard'], {})
    config_loader = ConfigLoader(args)
    with pytest.raises(AssertionException) as error:
        config_loader.get_umapi_options()
    assert "Your main configuration file is still in v1 format." in str(error.value)


def test_get_directory_connector_configs(cli_args, config_files):
    args = cli_args({'config_filename': config_files['root_config']})
    config_loader = ConfigLoader(args)
    config_loader.get_directory_connector_configs()

    # Test method to verify path is the value of the 'ldap' key
    expected_file_path = config_loader.main_config.value['directory_users']['connectors']['ldap']
    assert expected_file_path == config_files['ldap']

    # Test method to verify 'okta', 'csv', 'ldap' are in the accessed_keys set
    result = config_loader.main_config.child_configs.get('directory_users').child_configs['connectors'].accessed_keys
    assert result == {'okta', 'adobe_console', 'csv', 'ldap'}


def test_get_directory_connector_module_name(cli_args, config_files):
    args = cli_args({'config_filename': config_files['root_config']})
    config_loader = ConfigLoader(args)
    options = config_loader.invocation_options
    options['stray_list_input_path'] = 'something'
    assert not config_loader.get_directory_connector_module_name()

    options['directory_connector_type'] = 'csv'
    options['stray_list_input_path'] = None
    expected = 'user_sync.connector.directory_csv'
    assert config_loader.get_directory_connector_module_name() == expected

    options['directory_connector_type'] = None
    assert not config_loader.get_directory_connector_module_name()
