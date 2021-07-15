from __future__ import annotations
from unittest import TestCase
from unittest.mock import Mock, patch
from typing import List, Dict

import connection.jira_connection
from main import main
from config import Config
from connection.dynatrace_connection import EntityDetails


class TestMain(TestCase):

    SECURITY_PROBLEM_DATA = [{
        "securityProblemId": "the_id",
        "displayId": "the_display_id",
        "status": "OPEN",
        "muted": False,
        "vulnerabilityId": "the_vulnerability_id",
        "vulnerabilityType": "THIRD_PARTY",
        "title": "Man-in-the-Middle (MitM)",
        "url": "https://fake.example/the_id",
        "description": "vulnerability description",
        "technology": "the_tech",
        "firstSeenTimestamp": 1606738557942,
        "lastUpdatedTimestamp": 1620925877909,
        "riskAssessment": {
            "riskLevel": "MEDIUM",
            "riskScore": 4.3,
            "riskVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N/MC:N/MI:L",
            "baseRiskLevel": "MEDIUM",
            "baseRiskScore": 4.3,
            "baseRiskVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "exposure": "PUBLIC_NETWORK",
            "dataAssets": "REACHABLE",
            "publicExploit": "NOT_AVAILABLE"
        },
        "cveIds": [
            "CVE-2012-6153"
        ],
        "affectedEntities": [
            "PROCESS_GROUP_INSTANCE-1",
            "PROCESS_GROUP_INSTANCE-2",
            "PROCESS_GROUP_INSTANCE-3",
        ],
        "relatedEntities": {
            "services": [
                {
                    "id": "SERVICE-1",
                    "numberOfAffectedEntities": 1,
                    "affectedEntities": [
                        "PROCESS_GROUP_INSTANCE-1"
                    ],
                    "exposure": "NOT_DETECTED"
                },
                {
                    "id": "SERVICE-2",
                    "numberOfAffectedEntities": 1,
                    "affectedEntities": [
                        "PROCESS_GROUP_INSTANCE-2",
                    ],
                    "exposure": "NOT_DETECTED"
                },
                {
                    "id": "SERVICE-3",
                    "numberOfAffectedEntities": 1,
                    "affectedEntities": [
                        "PROCESS_GROUP_INSTANCE-3"
                    ],
                    "exposure": "PUBLIC_NETWORK"
                }
            ],
            "hosts": [
                {
                    "id": "HOST-1",
                    "numberOfAffectedEntities": 2,
                    "affectedEntities": [
                        "PROCESS_GROUP_INSTANCE-1",
                        "PROCESS_GROUP_INSTANCE-2"
                    ]
                },
                {
                    "id": "HOST-2",
                    "numberOfAffectedEntities": 1,
                    "affectedEntities": [
                        "PROCESS_GROUP_INSTANCE-3",
                    ]
                }
            ],
            "databases": [
                "SERVICE-4",
                "SERVICE-5"
            ],
            "kubernetesWorkloads": [],
            "kubernetesClusters": []
        },
        "vulnerableComponents": [
            {
                "id": "SOFTWARE_COMPONENT-1",
                "displayName": "component:1.2",
                "fileName": "component-1.2.lib",
                "numberOfAffectedEntities": 3,
                "affectedEntities": [
                    "PROCESS_GROUP_INSTANCE-1",
                    "PROCESS_GROUP_INSTANCE-2",
                    "PROCESS_GROUP_INSTANCE-3",
                ]
            }
        ],
    }]

    AFFECTED_ENTITY_DETAILS = [
        {
            'entityId': 'PROCESS_GROUP_INSTANCE-1',
            'displayName': "process1",
            'tags': []
        },
        {
            'entityId': 'PROCESS_GROUP_INSTANCE-2',
            'displayName': "process2",
            'tags': []
        },
        {
            'entityId': 'PROCESS_GROUP_INSTANCE-3',
            'displayName': "process3",
            'tags': []
        }
    ]

    RELATED_ENTITY_DETAILS = [
        {
            'entityId': 'HOST-1',
            'displayName': "host1",
            'tags': []
        },
        {
            'entityId': 'HOST-2',
            'displayName': "host2",
            'tags': []
        },
        {
            'entityId': 'HOST-3',
            'displayName': "host3",
            'tags': []
        }
    ]

    def setUp(self):
        self.config_dict = {"dt_conn":
                            {
                                "url": "http://example.com/api/v2",
                                "token": "my-secret-token"
                            },
                            "jira_conn":
                            {
                                "url": "http://example.com:8080",
                                "username": "my-user",
                                "password": "my-pass"
                            },
                            "rules": [
                             {
                                "type": "hostname",
                                "value": "foo",
                                "operator": "startswith",
                                "minimumScore": 8.0,
                                "stopAfterMatch": True,
                                "params":
                                {
                                    "project": "baz",
                                    "label": "security_emergency"
                                }
                              }
                             ],
                            "jira_defaults":
                            {
                                "assignee": "",
                                "project": "MY_JIRA_PROJECT",
                                "label": "",
                                "priority": "High",
                                "issuetype": "Bug"
                            },
                            "ignore_rest": False}

    @staticmethod
    def convert_entity_responses(entity_responses: List[Dict]) -> Dict[str, EntityDetails]:
        return {x['entityId']: EntityDetails(**x) for x in entity_responses}

    def test_works_with_no_data_received(self):
        fake_conn = Mock()
        fake_conn.get_open_security_problems.return_value = []
        config = Config(**self.config_dict)
        main(config, fake_conn, dry_run=True)

    @patch.object(connection.jira_connection.JiraConnection, 'create_issue')
    def test_no_rule_matches_default_action_triggers(self, mocked_create_issue):
        fake_conn = Mock()
        fake_conn.get_open_security_problems.return_value = self.SECURITY_PROBLEM_DATA
        fake_conn.get_entity_details.side_effect = [
            TestMain.convert_entity_responses(self.AFFECTED_ENTITY_DETAILS),
            TestMain.convert_entity_responses(self.RELATED_ENTITY_DETAILS)]
        config = Config(**self.config_dict)
        main(config, fake_conn, dry_run=True)
        self.assertEqual(1, mocked_create_issue.call_count)

    @patch.object(connection.jira_connection.JiraConnection, 'create_issue')
    def test_rule_matches_default_action_triggers(self, mocked_create_issue):
        fake_conn = Mock()
        fake_conn.get_open_security_problems.return_value = self.SECURITY_PROBLEM_DATA
        fake_conn.get_entity_details.side_effect = [
            TestMain.convert_entity_responses(self.AFFECTED_ENTITY_DETAILS),
            TestMain.convert_entity_responses(self.RELATED_ENTITY_DETAILS)]

        new_rule = {
            "type": "hostname",
            "value": "host1",
            "operator": "equals",
            "params": {
                "label": "host1-issue"
            }
        }

        self.config_dict['rules'].append(new_rule)

        config = Config(**self.config_dict)
        main(config, fake_conn, dry_run=True)
        self.assertEqual(2, mocked_create_issue.call_count)

    @patch.object(connection.jira_connection.JiraConnection, 'create_issue')
    def test_rule_matches_default_action_does_not_trigger(self, mocked_create_issue):
        fake_conn = Mock()
        fake_conn.get_open_security_problems.return_value = self.SECURITY_PROBLEM_DATA
        fake_conn.get_entity_details.side_effect = [
            TestMain.convert_entity_responses(self.AFFECTED_ENTITY_DETAILS),
            TestMain.convert_entity_responses(self.RELATED_ENTITY_DETAILS)]

        self.config_dict['ignore_rest'] = True
        config = Config(**self.config_dict)
        main(config, fake_conn, dry_run=True)
        self.assertEqual(0, mocked_create_issue.call_count)

    @patch.object(connection.jira_connection.JiraConnection, 'add_comment')
    @patch.object(connection.jira_connection.JiraConnection, 'get_issues_with_summary_prefix')
    def test_comment_is_created_for_existing_issue(self, mocked_add_comment, mocked_get_issues):
        fake_conn = Mock()
        fake_conn.get_open_security_problems.return_value = self.SECURITY_PROBLEM_DATA
        fake_conn.get_entity_details.side_effect = [
            TestMain.convert_entity_responses(self.AFFECTED_ENTITY_DETAILS),
            TestMain.convert_entity_responses(self.RELATED_ENTITY_DETAILS)]
        mocked_get_issues.return_value = ['123']
        config = Config(**self.config_dict)
        main(config, fake_conn, dry_run=True, add_comments=True)
        self.assertEqual(1, mocked_add_comment.call_count)
