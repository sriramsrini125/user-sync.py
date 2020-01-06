import csv
import re
from copy import deepcopy

import mock
import pytest
import six
import yaml
from mock import MagicMock

from tests.util import compare_iter
from user_sync.rules import RuleProcessor, AdobeGroup, UmapiTargetInfo
from user_sync.rules import UmapiConnectors


@pytest.fixture
def rule_processor():
    return RuleProcessor({})


@pytest.fixture()
def mock_umapi_connectors():
    def _mock_umapi_connectors(*args):
        return UmapiConnectors(
            MockUmapiConnector(),
            {a: MockUmapiConnector(name=a) for a in args})

    return _mock_umapi_connectors


@pytest.fixture()
def mock_umapi_info():
    def _mock_umapi_info(name='primary', groups=[]):
        mock_umapi_info = UmapiTargetInfo(name)
        for g in groups:
            mock_umapi_info.add_mapped_group(g)
        return mock_umapi_info

    return _mock_umapi_info


class MockUmapiConnector(MagicMock):
    class MockActionManager:
        def get_statistics(self):
            return 10, 2

    def __init__(self, name='', options={}, *args, **kwargs):
        super(MockUmapiConnector, self).__init__(*args, **kwargs)
        self.name = 'umapi' + name
        self.options = options
        self.action_manager = MockUmapiConnector.MockActionManager()

    def get_action_manager(self):
        return self.action_manager


def test_log_action_summary(rule_processor, log_stream, mock_umapi_connectors):
    connectors = mock_umapi_connectors('umapi-2', 'umapi-3')
    stream, logger = log_stream
    rule_processor.logger = logger
    rule_processor.log_action_summary(connectors)
    expected = """---------------------------------- Action Summary ----------------------------------
                                Number of directory users read: 0
                  Number of directory users selected for input: 0
                                    Number of Adobe users read: 0
                   Number of Adobe users excluded from updates: 0
            Number of non-excluded Adobe users with no changes: 0
                               Number of new Adobe users added: 0
                        Number of matching Adobe users updated: 0
                           Number of Adobe user-groups created: 0
                    Number of Adobe users added to secondaries: 0
  Number of primary UMAPI actions sent (total, success, error): (10, 8, 2)
  Number of umapi-2 UMAPI actions sent (total, success, error): (10, 8, 2)
  Number of umapi-3 UMAPI actions sent (total, success, error): (10, 8, 2)
------------------------------------------------------------------------------------
"""
    assert expected == stream.getvalue()


def test_read_desired_user_groups_basic(rule_processor, mock_directory_user):
    rp = rule_processor
    mock_directory_user['groups'] = ['Group A', 'Group B']

    directory_connector = mock.MagicMock()
    directory_connector.load_users_and_groups.return_value = [mock_directory_user]
    mappings = {
        'Group A': [AdobeGroup.create('Console Group')]}
    rp.read_desired_user_groups(mappings, directory_connector)

    # Assert the security group and adobe group end up in the correct scope
    assert "Group A" in rp.after_mapping_hook_scope['source_groups']
    assert "Console Group" in rp.after_mapping_hook_scope['target_groups']

    # Assert the user group updated in umapi info
    user_key = rp.get_directory_user_key(mock_directory_user)
    assert ('console group' in rp.umapi_info_by_name[None].desired_groups_by_user_key[user_key])
    assert user_key in rp.filtered_directory_user_by_user_key


def test_after_mapping_hook(rule_processor, mock_directory_user):
    rp = rule_processor
    mock_directory_user['groups'] = ['Group A']
    directory_connector = mock.MagicMock()
    directory_connector.load_users_and_groups.return_value = [mock_directory_user]

    # testing after_mapping_hooks
    after_mapping_hook_text = """
first = source_attributes.get('givenName')
if first is not None: 
  target_groups.add('ext group 1')
target_groups.add('ext group 2')
"""

    AdobeGroup.create('existing_group')
    rp.options['after_mapping_hook'] = compile(
        after_mapping_hook_text, '<per-user after-mapping-hook>', 'exec')

    rp.read_desired_user_groups({}, directory_connector)
    assert "Group A" in rp.after_mapping_hook_scope['source_groups']
    assert "ext group 1" in rp.after_mapping_hook_scope['target_groups']
    assert "ext group 2" in rp.after_mapping_hook_scope['target_groups']


def test_additional_groups(rule_processor, log_stream, mock_directory_user):
    rp = rule_processor
    mock_directory_user['member_groups'] = ['other_security_group', 'security_group', 'more_security_group']

    directory_connector = mock.MagicMock()
    directory_connector.load_users_and_groups.return_value = [mock_directory_user]
    user_key = rp.get_directory_user_key(mock_directory_user)

    rp.options['additional_groups'] = [
        {
            'source': re.compile('other(.+)'),
            'target': AdobeGroup.create('additional_user_group')},
        {
            'source': re.compile('security_group'),
            'target': AdobeGroup.create('additional(.+)')}
    ]

    rp.read_desired_user_groups({}, directory_connector)
    assert 'other_security_group' in rp.umapi_info_by_name[None].additional_group_map['additional_user_group']
    assert 'security_group' in rp.umapi_info_by_name[None].additional_group_map['additional(.+)']
    assert {'additional_user_group', 'additional(.+)'}.issubset(
        rp.umapi_info_by_name[None].desired_groups_by_user_key[user_key])


@mock.patch("user_sync.rules.RuleProcessor.update_umapi_users_for_connector")
def test_sync_umapi_users(update_umapi, rule_processor, mock_umapi_connectors, mock_user_directory_data,
                          mock_umapi_info):
    # Create 3 umapi connectors - 1 primary, 2 secondary
    secondary_umapi_name = 'umapi-2'
    third_umapi_name = 'umapi-3'
    umapi_connectors = mock_umapi_connectors(secondary_umapi_name, third_umapi_name)
    umapi_info = mock_umapi_info(secondary_umapi_name, "Group")

    # Add the umapi infos + group for secondaries so they will not be skipped
    rule_processor.umapi_info_by_name[secondary_umapi_name] = umapi_info
    rule_processor.umapi_info_by_name[third_umapi_name] = umapi_info

    # Use a mock object here to collect the calls made for validation
    rule_processor.create_umapi_user = mock.MagicMock()

    # Just prepare a list of users from the mock data in the form of user_key:groups
    # We use a mock method call to return users from the update commands
    refined_users = {k: set(v.pop('groups')) for k, v in six.iteritems(mock_user_directory_data)}
    primary_users = {k: refined_users[k] for k in list(refined_users.keys())[0:2]}
    secondary_users = {k: refined_users[k] for k in list(refined_users.keys())[2:3]}
    third_users = {k: refined_users[k] for k in list(refined_users.keys())[3:]}
    update_umapi.side_effect = [primary_users, secondary_users, third_users]
    rule_processor.sync_umapi_users(umapi_connectors)

    # Check that the users were correctly returned and sorted from update_umapi_users calls
    assert compare_iter(rule_processor.primary_users_created, primary_users.keys())
    assert compare_iter(rule_processor.secondary_users_created, list(refined_users.keys())[2:])

    # Checks that create user was called for all of the users
    results = [c[1][0:2] for c in rule_processor.create_umapi_user.mock_calls]
    actual = [(k, v) for k, v in six.iteritems(refined_users)]
    assert compare_iter(results, actual)


def test_create_umapi_groups(rule_processor, log_stream, mock_umapi_connectors, mock_umapi_info):
    stream, logger = log_stream
    rule_processor.logger = logger
    secondary_umapi_name = 'umapi-2'

    uc = mock_umapi_connectors(secondary_umapi_name)
    sec_conn = uc.secondary_connectors[secondary_umapi_name]
    sec_conn.get_groups.return_value = {}
    uc.primary_connector.get_groups.return_value = [
        {
            'groupId': 94663221,
            'groupName': 'existing_group',
            'type': 'SYSADMIN_GROUP',
            'memberCount': 41},
        {
            'groupId': 94663220,
            'groupName': 'misc_group',
            'type': 'SYSADMIN_GROUP',
            'memberCount': 150
        }
    ]

    primary_info = mock_umapi_info(groups=['new_group', 'existing_group'])
    sec_info = mock_umapi_info(secondary_umapi_name, ['new_group_2', 'new_group_3'])
    rule_processor.umapi_info_by_name = {
        None: primary_info,
        sec_conn.name: sec_info}
    rule_processor.create_umapi_groups(uc)

    calls = [c[1] for c in uc.primary_connector.mock_calls]
    calls.extend([c[1] for c in sec_conn.mock_calls])
    calls = [c[0] for c in calls if c]
    assert compare_iter(calls, ['new_group', 'new_group_2', 'new_group_3'])


def test_process_strays(rule_processor, log_stream):
    stream, logger = log_stream
    rule_processor.logger = logger
    rule_processor.will_manage_strays = True
    with mock.patch("user_sync.rules.RuleProcessor.manage_strays"):
        rule_processor.stray_key_map = {
            None: {
                'federatedID,testuser2000@example.com,': set()}}
        rule_processor.process_strays({})

        stream.flush()
        actual_logger_output = stream.getvalue()
        assert "Processing Adobe-only users..." in actual_logger_output

    rule_processor.options["max_adobe_only_users"] = 0
    rule_processor.process_strays({})
    stream.flush()
    actual_logger_output = stream.getvalue()
    assert "Unable to process Adobe-only users" in actual_logger_output
    assert rule_processor.action_summary["primary_strays_processed"] == 0

    rule_processor.primary_user_count = 10
    rule_processor.excluded_user_count = 1
    rule_processor.options["max_adobe_only_users"] = "5%"
    rule_processor.process_strays({})
    stream.flush()
    actual_logger_output = stream.getvalue()
    assert "Unable to process Adobe-only users" in actual_logger_output
    assert rule_processor.action_summary["primary_strays_processed"] == 0

    with mock.patch("user_sync.rules.RuleProcessor.manage_strays"):
        rule_processor.stray_key_map = {
            None: {
                'federatedID,testuser2000@example.com,': set()}}
        rule_processor.options["max_adobe_only_users"] = "20%"
        rule_processor.process_strays({})
        stream.flush()
        actual_logger_output = stream.getvalue()
        assert "Processing Adobe-only users..." in actual_logger_output


@mock.patch('user_sync.helper.CSVAdapter.read_csv_rows')
def test_stray_key_map(csv_reader, rule_processor):
    csv_mock_data = [
        {
            'type': 'adobeID',
            'username': 'removeuser2@example.com',
            'domain': 'example.com'},
        {
            'type': 'federatedID',
            'username': 'removeuser@example.com',
            'domain': 'example.com'},
        {
            'type': 'enterpriseID',
            'username': 'removeuser3@example.com',
            'domain': 'example.com'}
    ]

    csv_reader.return_value = csv_mock_data
    rule_processor.read_stray_key_map('')
    actual_value = rule_processor.stray_key_map
    expected_value = {
        None: {
            'federatedID,removeuser@example.com,': None,
            'enterpriseID,removeuser3@example.com,': None,
            'adobeID,removeuser2@example.com,': None}
    }

    assert expected_value == actual_value

    # Added secondary umapi value
    csv_mock_data = [
        {
            'type': 'adobeID',
            'username': 'remo@sample.com',
            'domain': 'sample.com',
            'umapi': 'secondary'},
        {
            'type': 'federatedID',
            'username': 'removeuser@example.com'},
        {
            'type': 'enterpriseID',
            'username': 'removeuser3@example.com',
            'domain': 'example.com'}

    ]
    csv_reader.return_value = csv_mock_data
    rule_processor.read_stray_key_map('')
    actual_value = rule_processor.stray_key_map
    expected_value = {
        'secondary': {
            'adobeID,remo@sample.com,': None
        },
        None: {
            'federatedID,removeuser@example.com,': None,
            'enterpriseID,removeuser3@example.com,': None,
            'adobeID,removeuser2@example.com,': None}
    }
    assert expected_value == actual_value


def test_get_user_attribute_difference(rule_processor, mock_directory_user):
    directory_user_mock_data = mock_directory_user
    umapi_users_mock_data = deepcopy(mock_directory_user)
    umapi_users_mock_data['firstname'] = 'Adobe'
    umapi_users_mock_data['lastname'] = 'Username'
    umapi_users_mock_data['email'] = 'adobe.username@example.com'

    expected = {
        'email': mock_directory_user['email'],
        'firstname': mock_directory_user['firstname'],
        'lastname': mock_directory_user['lastname']
    }

    assert expected == rule_processor.get_user_attribute_difference(
        directory_user_mock_data, umapi_users_mock_data)

    # test with no change
    assert rule_processor.get_user_attribute_difference(
        umapi_users_mock_data, umapi_users_mock_data) == {}


def test_log_after_mapping_hook_scope(log_stream):
    stream, logger = log_stream

    def compare_attr(text, target):
        s = yaml.safe_load(re.search('{.+}', text).group())
        for attr in s:
            if s[attr] != 'None':
                assert s[attr] == target[attr]

    state = {
        'source_attributes': {
            'email': 'bsisko@example.com',
            'identity_type': None,
            'username': None,
            'domain': None,
            'givenName': 'Benjamin',
            'sn': 'Sisko',
            'c': 'CA'},
        'source_groups': set(),
        'target_attributes': {
            'email': 'bsisko@example.com',
            'username': 'bsisko@example.com',
            'domain': 'example.com',
            'firstname': 'Benjamin',
            'lastname': 'Sisko',
            'country': 'CA'},
        'target_groups': set(),
        'log_stream': logger,
        'hook_storage': None
    }

    ruleprocessor = RuleProcessor({})
    ruleprocessor.logger = logger
    ruleprocessor.after_mapping_hook_scope = state
    ruleprocessor.log_after_mapping_hook_scope(before_call=True)
    stream.flush()
    x = stream.getvalue().split('\n')

    assert len(x[2]) < 32
    assert len(x[4]) < 32
    compare_attr(x[1], state['source_attributes'])
    compare_attr(x[3], state['target_attributes'])

    state['target_groups'] = {'One'}
    state['target_attributes']['firstname'] = 'John'
    state['source_attributes']['sn'] = 'David'
    state['source_groups'] = {'One'}

    ruleprocessor.after_mapping_hook_scope = state
    ruleprocessor.log_after_mapping_hook_scope(after_call=True)
    stream.flush()
    x = stream.getvalue().split('\n')

    assert re.search('(Target groups, after).*(One)', x[6])
    compare_attr(x[5], state['target_attributes'])


def test_get_umapi_user_key(rule_processor):
    mock_umapi_user_dict = {
        'email': '7of9@exmaple.com',
        'username': '7of9@example.com',
        'domain': 'example.com',
        'type': 'federatedID'
    }

    actual_result = rule_processor.get_umapi_user_key(mock_umapi_user_dict)
    assert actual_result == 'federatedID,7of9@example.com,'


def test_get_user_key(rule_processor):
    key = rule_processor.get_user_key("federatedID", "wriker@example.com", "wriker@example.com", "example.com")
    assert key == 'federatedID,wriker@example.com,'

    key = rule_processor.get_user_key("federatedID", "wriker", "example.com")
    assert key == 'federatedID,wriker,example.com'

    assert not rule_processor.get_user_key(None, "wriker@example.com", "wriker@example.com", "example.com")
    assert not rule_processor.get_user_key("federatedID", None, "wriker@example.com")


def test_get_username_from_user_key(rule_processor):
    with mock.patch('user_sync.rules.RuleProcessor.parse_user_key') as parse:
        parse.return_value = ['federatedID', 'test_user@email.com', '']
        username = rule_processor.get_username_from_user_key("federatedID,test_user@email.com,")
        assert username == 'test_user@email.com'


def test_parse_user_key(rule_processor):
    parsed_user_key = rule_processor.parse_user_key("federatedID,test_user@email.com,")
    assert parsed_user_key == ['federatedID', 'test_user@email.com', '']

    domain_parsed_key = rule_processor.parse_user_key("federatedID,test_user,email.com")
    assert domain_parsed_key == ['federatedID', 'test_user', 'email.com']


def test_add_mapped_group():
    umapi_target_info = UmapiTargetInfo("")
    umapi_target_info.add_mapped_group("All Students")
    assert "all students" in umapi_target_info.mapped_groups
    assert "All Students" in umapi_target_info.non_normalize_mapped_groups


def test_add_additional_group():
    umapi_target_info = UmapiTargetInfo("")
    umapi_target_info.add_additional_group('old_name', 'new_name')
    assert umapi_target_info.additional_group_map['old_name'][0] == 'new_name'


def test_add_desired_group_for():
    umapi_target_info = UmapiTargetInfo("")
    with mock.patch("user_sync.rules.UmapiTargetInfo.get_desired_groups") as mock_desired_groups:
        mock_desired_groups.return_value = None
        umapi_target_info.add_desired_group_for('user_key', 'group_name')
        assert umapi_target_info.desired_groups_by_user_key['user_key'] == {'group_name'}


def test_create():
    with mock.patch("user_sync.rules.AdobeGroup._parse") as parse:
        parse.return_value = ('group_name', None)
        AdobeGroup.create('this')
        assert ('group_name', None) in AdobeGroup.index_map


def test_parse():
    result = AdobeGroup._parse('qualified_name')
    assert result == ('qualified_name', None)


def test_add_stray(rule_processor):
    user_key_mock_data = 'federatedID,rules.user@example.com,'
    removed_groups_mock_data = {'aishtest'}
    rule_processor.stray_key_map = {
        None: {}}
    rule_processor.add_stray(None, user_key_mock_data, removed_groups_mock_data)
    assert rule_processor.stray_key_map[None][user_key_mock_data] == removed_groups_mock_data


def test_is_selected_user_key(rule_processor):
    compiled_expression = re.compile(r'\A' + "nuver.yusser@example.com" + r'\Z', re.IGNORECASE)
    rule_processor.options['username_filter_regex'] = compiled_expression
    result = rule_processor.is_selected_user_key('federatedID,nuver.yusser@example.com,')
    assert result
    result = rule_processor.is_selected_user_key('federatedID,test@test.com,')
    assert not result
    compiled_expression = re.compile(r'\A' + ".*sser@example.com" + r'\Z', re.IGNORECASE)
    rule_processor.options['username_filter_regex'] = compiled_expression
    result = rule_processor.is_selected_user_key('federatedID,nuver.yusser@example.com,')
    assert result


def test_is_umapi_user_excluded(rule_processor):
    in_primary_org = True
    rule_processor.exclude_identity_types = ['adobeID']
    user_key = 'adobeID,adobe.user@example.com,'
    current_groups = {'default acrobat pro dc configuration', 'one', '_admin_group a'}
    assert rule_processor.is_umapi_user_excluded(in_primary_org, user_key, current_groups)

    user_key = 'federatedID,adobe.user@example.com,'
    rule_processor.exclude_groups = {'one'}
    assert rule_processor.is_umapi_user_excluded(in_primary_org, user_key, current_groups)

    user_key = 'federatedID,adobe.user@example.com,'
    rule_processor.exclude_groups = set()
    compiled_expression = re.compile(r'\A' + "adobe.user@example.com" + r'\Z', re.IGNORECASE)
    rule_processor.exclude_users = {compiled_expression}
    assert rule_processor.is_umapi_user_excluded(in_primary_org, user_key, current_groups)


def test_write_stray_key_map(rule_processor, tmpdir):
    tmp_file = str(tmpdir.join('strays_test.csv'))

    rule_processor.stray_list_output_path = tmp_file
    rule_processor.stray_key_map = {
        'secondary': {
            'adobeID,remoab@example.com,': set(),
            'enterpriseID,adobe.user3@example.com,': set(), },
        None: {
            'enterpriseID,adobe.user1@example.com,': set(),
            'federatedID,adobe.user2@example.com,': set()
        }}

    rule_processor.write_stray_key_map()
    with open(tmp_file, 'r') as our_file:
        reader = csv.reader(our_file)
        actual = list(reader)
        expected = [['type', 'username', 'domain', 'umapi'],
                    ['adobeID', 'remoab@example.com', '', 'secondary'],
                    ['enterpriseID', 'adobe.user3@example.com', '', 'secondary'],
                    ['enterpriseID', 'adobe.user1@example.com', '', ''],
                    ['federatedID', 'adobe.user2@example.com', '', '']]
        assert compare_iter(actual, expected)


def test_create_umapi_commands_for_directory_user_update_username(rule_processor, mock_directory_user):
    result = rule_processor.create_umapi_commands_for_directory_user(mock_directory_user)
    assert len(result.do_list) == 1

    mock_directory_user['username'] = 'dummy@example.com'
    result = rule_processor.create_umapi_commands_for_directory_user(mock_directory_user)
    assert 'update' in result.do_list[1]
    assert len(result.do_list) == 2


def test_create_umapi_commands_for_directory_user_country_code(rule_processor, log_stream, mock_directory_user):
    stream, logger = log_stream
    rule_processor.logger = logger

    # Default Country Code as None and Id Type as federatedID. Country as None in mock_directory_user
    rule_processor.options['default_country_code'] = None
    mock_directory_user['country'] = None
    result = rule_processor.create_umapi_commands_for_directory_user(mock_directory_user)
    assert result == None
    stream.flush()
    actual_logger_output = stream.getvalue()
    assert "User cannot be added without a specified country code:" in actual_logger_output

    # Default Country Code as None with Id Type as enterpriseID. Country as None in mock_directory_user
    rule_processor.options['default_country_code'] = None
    mock_directory_user['identity_type'] = 'enterpriseID'
    result = rule_processor.create_umapi_commands_for_directory_user(mock_directory_user)
    assert result.do_list[0][1]['country'] == 'UD'

    # Having Default Country Code with value 'US'. Country as None in mock_directory_user.
    rule_processor.options['default_country_code'] = 'US'
    result = rule_processor.create_umapi_commands_for_directory_user(mock_directory_user)
    assert result.do_list[0][1]['country'] == 'US'

    # Country as 'CA' in mock_directory_user
    mock_directory_user['country'] = 'CA'
    result = rule_processor.create_umapi_commands_for_directory_user(mock_directory_user)
    assert result.do_list[0][1]['country'] == 'CA'


def test_update_umapi_users_for_connector(rule_processor, mock_user_directory_data, mock_umapi_user_data, log_stream):
    stream, logger = log_stream
    rule_processor.logger = logger
    rule_processor.options['process_groups'] = True
    rule_processor.will_process_strays = True
    umapi_connector = mock.MagicMock()
    umapi_connector.iter_users.return_value = mock_umapi_user_data
    umapi_info = mock.MagicMock()
    umapi_info.get_name.return_value = None
    umapi_info.get_desired_groups_by_user_key.return_value = {
        'federatedID,both1@example.com,': {'user_group'},
        'federatedID,directory.only1@example.com,': {'user_group'},
        'federatedID,both3@example.com,': {'user_group'}}
    umapi_info.get_umapi_user.return_value = None
    umapi_info.get_mapped_groups.return_value = {'user_group'}
    rule_processor.filtered_directory_user_by_user_key = mock_user_directory_data
    rule_processor.exclude_users = [re.compile('\\Aexclude1@example.com\\Z', re.IGNORECASE)]
    result_user_groups_to_map = rule_processor.update_umapi_users_for_connector(umapi_info, umapi_connector)
    umapi_info_methods_called = [c[0] for c in umapi_info.mock_calls]
    umapi_connector_methods_called = [c[0] for c in umapi_connector.mock_calls]
    stream.flush()
    logger_output = stream.getvalue()
    logger_output = re.sub('[\\[\\]]+', '', logger_output)
    logger_output = re.sub("{'user_group'}", "set('user_group')", logger_output)
    assert "Found Adobe-only user: federatedID,adobe.only1@example.com," in logger_output
    assert "Adobe user matched on customer side: federatedID,both1@example.com," in logger_output
    assert "Managing groups for user key: federatedID,both1@example.com, added: set('user_group') removed: set()" in logger_output
    assert "Managing groups for user key: federatedID,both2@example.com, added: set() removed: set('user_group')" in logger_output
    assert "Managing groups for user key: federatedID,both3@example.com," not in logger_output
    assert "Excluding adobe user (due to name): federatedID,exclude1@example.com," in logger_output
    assert 'set_umapi_users_loaded' in umapi_info_methods_called
    assert 'send_commands' in umapi_connector_methods_called
    assert rule_processor.stray_key_map == {
        None: {
            'federatedID,adobe.only1@example.com,': set()}}
    assert result_user_groups_to_map == {
        'federatedID,directory.only1@example.com,': {'user_group'}}


def test_update_umapi_user(rule_processor, log_stream, mock_umapi_user):
    stream, logger = log_stream
    rule_processor.logger = logger

    mock_user_key = 'federatedID,both1@example.com,'
    mock_groups_to_add = {'added_user_group'}
    mock_groups_to_remove = {'removed_user_group'}
    mock_attributes_to_update = {
        'firstname': 'newfirstname',
        'email': 'newemail'
    }

    mock_umapi_user["groups"] = ["removed_user_group", "org"]
    mock_umapi_user['username'] = 'different@example.com'

    umapi_connector = mock.MagicMock()
    with mock.patch('user_sync.connector.umapi.Commands') as commands:
        commands.return_value = mock.MagicMock()
        rule_processor.update_umapi_user(UmapiTargetInfo(None), mock_user_key, umapi_connector,
                                         mock_attributes_to_update,
                                         mock_groups_to_add, mock_groups_to_remove, mock_umapi_user)
        commands_sent = str(umapi_connector.send_commands.call_args[0][0].method_calls)
        commands_sent = re.sub("set\\(\\[", "{", commands_sent)
        commands_sent = re.sub("\\]\\)", "}", commands_sent)
        assert "update_user" in commands_sent
        assert 'username' in commands_sent and "'firstname': 'newfirstname'" in commands_sent and "'email': 'newemail'" in commands_sent
        assert "remove_groups({'removed_user_group'})" in commands_sent
        assert "add_groups({'added_user_group'})" in commands_sent

    stream.flush()
    actual_logger_output = stream.getvalue()
    assert 'newfirstname' in actual_logger_output
    assert 'removed_user_group' in actual_logger_output
    assert 'added_user_group' in actual_logger_output
    assert mock_umapi_user["email"] == mock_umapi_user["username"]


@mock.patch("user_sync.rules.RuleProcessor.create_umapi_commands_for_directory_user")
def test_create_umapi_user(create_commands, rule_processor):
    rule_processor.directory_user_by_user_key['test'] = 'test'

    mock_command = MagicMock()
    create_commands.return_value = mock_command
    rule_processor.options['process_groups'] = True
    rule_processor.push_umapi = True
    rule_processor.create_umapi_user('test', set(), MagicMock(), MagicMock())

    called = [c[0] for c in mock_command.mock_calls][1:]
    assert called == ['remove_groups', 'add_groups']
