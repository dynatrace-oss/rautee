from unittest import TestCase
from unittest.mock import Mock, patch
from connection.dynatrace_connection import DynatraceConnection


class TestDynatraceConnection(TestCase):

    GOOD_LIST_RESPONSE_1 = {
        'totalCount': 2,
        'pageSize': 1,
        'nextPageKey': 'foo',
        'securityProblems': [
            {
                'securityProblemId': 'bar1',
            }
        ],
    }

    GOOD_LIST_RESPONSE_2 = {
        'totalCount': 2,
        'pageSize': 1,
        'nextPageKey': None,
        'securityProblems': [
            {
                'securityProblemId': 'bar2',
            }
        ],
    }

    GOOD_DETAIL_RESPONSE = {
        'foo': 1
    }

    GOOD_HOSTNAMES_RESPONSE = {
        'entityId': '1',
        'displayName': "host1",
    }

    GOOD_PROCESSES_RESPONSE = {
        'entityId': '2',
        'displayName': "process1"
    }

    def test_init(self):
        self.assertRaises(ValueError, DynatraceConnection, None, None)
        self.assertRaises(ValueError, DynatraceConnection, "", "")
        self.assertRaises(ValueError, DynatraceConnection, "foo", None)
        self.assertRaises(ValueError, DynatraceConnection, "http://foo", None)
        self.assertRaises(ValueError, DynatraceConnection, "http://foo/", None)
        self.assertRaises(ValueError, DynatraceConnection, "http://foo/", "")

        conn = DynatraceConnection("http://foo/", "my-fake-token")
        self.assertEqual(conn.url, "http://foo/")
        self.assertEqual(conn.token, "my-fake-token")

    @patch('requests.get', autospec=True)
    def test_get_open_security_problems(self, fake_get):
        fake_responses = [Mock(), Mock(), Mock(), Mock()]
        fake_responses[0].json.return_value = self.GOOD_LIST_RESPONSE_1
        fake_responses[0].status_code = 200
        fake_responses[1].json.return_value = self.GOOD_DETAIL_RESPONSE
        fake_responses[1].status_code = 200
        fake_responses[2].json.return_value = self.GOOD_LIST_RESPONSE_2
        fake_responses[2].status_code = 200
        fake_responses[3].json.return_value = self.GOOD_DETAIL_RESPONSE
        fake_responses[3].status_code = 200
        fake_get.side_effect = fake_responses

        conn = DynatraceConnection("http://fake_url/", "my-fake-token")
        security_problems = conn.get_open_security_problems()
        self.assertEqual(len(security_problems), 2)
        self.assertEqual(security_problems[0]['foo'], 1)
        self.assertEqual(security_problems[1]['foo'], 1)

    @patch('requests.get', autospec=True)
    def test_get_open_security_problems_raises_on_http_error(self, fake_get):
        fake_responses = [Mock()]
        fake_responses[0].json.return_value = self.GOOD_LIST_RESPONSE_1
        fake_responses[0].status_code = 403
        fake_get.side_effect = fake_responses

        conn = DynatraceConnection("http://fake_url/", "my-fake-token")
        self.assertRaises(ValueError, conn.get_open_security_problems)

    @patch('requests.get', autospec=True)
    def test_get_hostnames(self, fake_get):
        fake_get.return_value = Mock()
        fake_get.return_value.json.return_value = self.GOOD_HOSTNAMES_RESPONSE
        fake_get.return_value.status_code = 200

        conn = DynatraceConnection("http://fake_url/", "my-fake-token")
        hosts_id2name = conn.get_hostnames(['1'])
        self.assertEqual(len(hosts_id2name), 1)
        self.assertEqual(hosts_id2name['1'], 'host1')

    @patch('requests.get', autospec=True)
    def test_get_processes(self, fake_get):
        fake_get.return_value = Mock()
        fake_get.return_value.json.return_value = self.GOOD_PROCESSES_RESPONSE
        fake_get.return_value.status_code = 200

        conn = DynatraceConnection("http://fake_url/", "my-fake-token")
        processes_id2name = conn.get_process_names(['2'])
        self.assertEqual(len(processes_id2name), 1)
        self.assertEqual(processes_id2name['2'], 'process1')
