import mock
import pytest
import os
import csv
from user_sync.rules import RuleProcessor
import collections


@pytest.fixture
def rule_processor(caller_options):
    return RuleProcessor(caller_options)


@pytest.fixture
def caller_options():
    return {'adobe_group_filter': None, 'after_mapping_hook': None, 'default_country_code': 'US',
            'delete_strays': False, 'directory_group_filter': None, 'disentitle_strays': False, 'exclude_groups': [],
            'exclude_identity_types': ['adobeID'], 'exclude_strays': False, 'exclude_users': [],
            'extended_attributes': None, 'process_groups': True, 'max_adobe_only_users': 200,
            'new_account_type': 'federatedID', 'remove_strays': True, 'strategy': 'sync',
            'stray_list_input_path': None, 'stray_list_output_path': None,
            'test_mode': True, 'update_user_info': False, 'username_filter_regex': None,
            'adobe_only_user_action': ['remove'], 'adobe_only_user_list': None,
            'adobe_users': ['all'], 'config_filename': 'tests/fixture/user-sync-config.yml',
            'connector': 'ldap', 'encoding_name': 'utf8', 'user_filter': None,
            'users': None, 'directory_connector_type': 'csv',
            'directory_connector_overridden_options': {'file_path': None},
            'adobe_group_mapped': False, 'additional_groups': []}


@mock.patch('user_sync.helper.CSVAdapter.read_csv_rows')
def test_stray_key_map(csv_reader, rule_processor):
    csv_mock_data = [{'type': 'adobeID', 'username': 'removeuser2@example.com', 'domain': 'example.com'},
                     {'type': 'federatedID', 'username': 'removeuser@example.com', 'domain': 'example.com'},
                     {'type': 'enterpriseID', 'username': 'removeuser3@example.com', 'domain': 'example.com'}]
    csv_reader.return_value = csv_mock_data
    rule_processor.read_stray_key_map('')
    actual_value = rule_processor.stray_key_map
    expected_value = {None: {'federatedID,removeuser@example.com,': None,
                             'enterpriseID,removeuser3@example.com,': None,
                             'adobeID,removeuser2@example.com,': None}}

    assert expected_value == actual_value

    # Added secondary umapi value
    csv_mock_data = [{'type': 'adobeID', 'username': 'remo@example.com', 'domain': 'example.com', 'umapi': 'secondary'},
                     {'type': 'federatedID', 'username': 'removeuser@example.com'},
                     {'type': 'enterpriseID', 'username': 'removeuser3@example.com', 'domain': 'example.com'}]
    csv_reader.return_value = csv_mock_data
    rule_processor.read_stray_key_map('')
    actual_value = rule_processor.stray_key_map
    expected_value = {'secondary': {'adobeID,remo@example.com,': None},
                      None: {'federatedID,removeuser@example.com,': None,
                             'enterpriseID,removeuser3@example.com,': None,
                             'adobeID,removeuser2@example.com,': None}}
    assert expected_value == actual_value


def test_write_stray_key_map(rule_processor, log_stream, tmpdir):
    tmp_file = str(tmpdir.join('strays_test.csv'))
    stream, logger = log_stream
    rule_processor.logger = logger

    rule_processor.stray_list_output_path = tmp_file
    rule_processor.stray_key_map = {
        'secondary': {'adobeID,remoab@example.com,': set(), 'enterpriseID,adobe.user3@example.com,': set(), },
        None: {'enterpriseID,adobe.user1@example.com,': set(),
               'federatedID,adobe.user2@example.com,': set()
               }}
    rule_processor.write_stray_key_map()

    stream.flush()
    actual_logger_output = stream.getvalue()

    output_filename = rule_processor.stray_list_output_path
    length_of_adobe_only_users = str(len(rule_processor.stray_key_map[None]))

    assert output_filename in actual_logger_output
    assert length_of_adobe_only_users in actual_logger_output

    with open(tmp_file, 'r') as our_file:
        reader = csv.reader(our_file)
        actual = list(reader)
        expected = [['type', 'username', 'domain', 'umapi'],
                    ['enterpriseID', 'adobe.user1@example.com', '', ''],
                    ['federatedID', 'adobe.user2@example.com', '', ''],
                    ['adobeID', 'remoab@example.com', '', 'secondary'],
                    ['enterpriseID', 'adobe.user3@example.com', '', 'secondary']]
        actual_str = [','.join(r) for r in actual]
        expected_str = [','.join(r) for r in expected]
        for row in actual_str[1:3]:
            assert row in expected_str[1:3]
        for row in actual_str[3:5]:
            assert row in expected_str[3:5]
