from unittest import TestCase
from unittest.mock import MagicMock
from connection.jira_connection import JiraConnection


class TestJiraConnection(TestCase):

    DEFAULT_PARAMS = {
        'project': 'my_proj',
        'issuetype': 'Bug',
        'priority': 'HIGH'
    }

    EXTENDED_DEFAULT_PARAMS = {
        'project': 'my_proj',
        'issuetype': 'Bug',
        'priority': 'High',
        'assignee': 'Frank',
        'label': 'white'
    }

    CUSTOM_PARAMS = {
        'project': 'my_other_proj',
        'label': 'black'
    }

    def test_init_fails_on_missing_required_parameters(self):
        self.assertRaises(ValueError, JiraConnection, '', 'user', 'pass', {'project': 'proj', 'issuetype': 't'})
        self.assertRaises(ValueError, JiraConnection, 'url', '', 'pass', {'project': 'proj', 'issuetype': 't'})
        self.assertRaises(ValueError, JiraConnection, 'url', 'user', '', {'project': 'proj', 'issuetype': 't'})
        self.assertRaises(ValueError, JiraConnection, 'url', 'user', 'pass', {})
        self.assertRaises(ValueError, JiraConnection, 'url', 'user', 'pass', {'project': 'p'})
        self.assertRaises(ValueError, JiraConnection, 'url', 'user', 'pass', {'issuetype': 't'})
        self.assertRaises(ValueError, JiraConnection, 'url', 'user', 'pass', {'project': '', 'issuetype': 't'})
        self.assertRaises(ValueError, JiraConnection, 'url', 'user', 'pass', {'project': 'p', 'issuetype': ''})

    def test_create_issue_basic(self):
        jira_conn = JiraConnection('url', 'user', 'pass', self.DEFAULT_PARAMS)
        mock = MagicMock()
        jira_conn.authed_jira = mock
        jira_conn.create_issue("summary", "description", {})
        mock.create_issue.assert_called()
        mock.assign_issue.assert_not_called()

    def test_create_issue_with_extended_parameters(self):
        jira_conn = JiraConnection('url', 'user', 'pass', self.EXTENDED_DEFAULT_PARAMS)
        mock = MagicMock()
        jira_conn.authed_jira = mock
        jira_conn.create_issue("summary", "description", {})
        mock.create_issue.assert_called()
        mock.assign_issue.assert_called()

    def test_create_issue_respects_dryrun_parameter(self):
        jira_conn = JiraConnection('url', 'user', 'pass', self.EXTENDED_DEFAULT_PARAMS, dry_run=True)
        mock = MagicMock()
        jira_conn.authed_jira = mock
        jira_conn.create_issue("summary", "description", {})
        mock.create_issue.assert_not_called()
        mock.assign_issue.assert_not_called()

    def test_get_params_with_empty_custom_params(self):
        jira = JiraConnection('url', 'user', 'pass', self.DEFAULT_PARAMS)
        self.assertEqual(jira._get_params({}), self.DEFAULT_PARAMS)

    def test_get_params_none_values_are_ignored(self):
        jira = JiraConnection('url', 'user', 'pass', self.DEFAULT_PARAMS)
        self.assertEqual(jira._get_params({'project': None}), self.DEFAULT_PARAMS)

    def test_get_params_custom_params_take_precedence_over_default_params(self):
        jira = JiraConnection('url', 'user', 'pass', self.DEFAULT_PARAMS)
        params1 = jira._get_params(self.CUSTOM_PARAMS)
        self.assertTrue(all([params1[x] == self.CUSTOM_PARAMS[x] for x in self.CUSTOM_PARAMS.keys()]))
        self.assertTrue(all([x in params1 for x in self.DEFAULT_PARAMS.keys()]))

    def test_get_params_is_safe_to_be_called_multiple_times(self):
        jira = JiraConnection('url', 'user', 'pass', self.DEFAULT_PARAMS)
        params1 = jira._get_params(self.CUSTOM_PARAMS)
        params2 = jira._get_params(params1)
        self.assertDictEqual(jira.default_params, self.DEFAULT_PARAMS)
        self.assertDictEqual(params1, params2)
        self.assertNotEqual(jira.default_params, params1)
