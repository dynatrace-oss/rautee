from unittest import TestCase
from security_data import SecurityData
from rules.hostname_rule import HostnameRule
from connection.dynatrace_connection import EntityDetails


class TestHostnameRule(TestCase):

    SECURITY_PROBLEM_DATA = {
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
    }

    def setUp(self) -> None:

        all_affected_entities = {
                            'PROCESS_GROUP_INSTANCE-1':
                            EntityDetails(entityId='PROCESS_GROUP_INSTANCE-1', displayName='process1', tags=[]),
                            'PROCESS_GROUP_INSTANCE-2':
                            EntityDetails(entityId='PROCESS_GROUP_INSTANCE-2', displayName='process2', tags=[]),
                            'PROCESS_GROUP_INSTANCE-3':
                            EntityDetails(entityId='PROCESS_GROUP_INSTANCE-3', displayName='process3', tags=[]),
        }
        all_related_hosts = {
                            'HOST-1':
                            EntityDetails(entityId='HOST-1', displayName='host1', tags=[]),
                            'HOST-2':
                            EntityDetails(entityId='HOST-2', displayName='host2', tags=[]),
                            }
        self.security_data = SecurityData.create(self.SECURITY_PROBLEM_DATA, all_affected_entities, all_related_hosts)

    def test_init_unsupported_operator(self):
        rule = ['random', 'not_supported', None, False, {'foo': 'bar'}]
        self.assertRaises(ValueError, HostnameRule, *rule)

    def test_empty_string_match_works(self):
        rule = ['', 'contains', None, False, {'foo': 'bar'}]
        hostname_rule = HostnameRule(*rule)
        m, r = hostname_rule.match(self.security_data)
        self.assertEqual(self.security_data, m)
        self.assertEqual(0, len(r.related_hostnames))

    def test_match_partial_match(self):
        rule = ['host1', 'startswith', None, False, {'foo': 'bar'}]
        hostname_rule = HostnameRule(*rule)
        m, r = hostname_rule.match(self.security_data)
        self.assertEqual(1, len(m.related_hostnames))
        self.assertEqual(1, len(r.related_hostnames))
        self.assertIn('host1', m.related_hostnames)
        self.assertNotIn('host2', m.related_hostnames)
        self.assertNotIn('host1', r.related_hostnames)
        self.assertIn('host2', r.related_hostnames)

    def test_match_no_match(self):
        rule = ['not_matching', 'startswith', None, False, {'foo': 'bar'}]
        hostname_rule = HostnameRule(*rule)
        m, r = hostname_rule.match(self.security_data)
        self.assertEqual(None, m)
        self.assertEqual(2, len(r.related_hostnames))

    def test_match_full_match(self):
        rule = ['host', 'contains', None, False, {'foo': 'bar'}]
        hostname_rule = HostnameRule(*rule)
        m, r = hostname_rule.match(self.security_data)
        self.assertEqual(2, len(m.related_hostnames))
        self.assertEqual(0, len(r.related_hostnames))

    def test_stop_after_match(self):
        rule = ['host1', 'startswith', None, True, {'foo': 'bar'}]
        hostname_rule = HostnameRule(*rule)
        m, r = hostname_rule.match(self.security_data)
        self.assertListEqual(['host1', 'host2'], m.related_hostnames)
        self.assertEqual(None, r)

    def test_minimum_score_too_low(self):
        rule = ['host', 'containsIgnoreCase', self.security_data.risk_score + 1, False, {'foo': 'bar'}]
        hostname_rule = HostnameRule(*rule)
        m, r = hostname_rule.match(self.security_data)
        self.assertEqual(None, m)
        self.assertEqual(self.security_data, r)

    def test_minimum_score_equals(self):
        rule = ['host', 'containsIgnoreCase', None, False, {'foo': 'bar'}]
        hostname_rule = HostnameRule(*rule)
        m, r = hostname_rule.match(self.security_data)
        self.assertEqual(self.security_data, m)
        self.assertEqual(0, len(r.related_hostnames))

    def test_minimum_score_higher(self):
        rule = ['host', 'containsIgnoreCase', self.security_data.risk_score - 1, False, {'foo': 'bar'}]
        hostname_rule = HostnameRule(*rule)
        m, r = hostname_rule.match(self.security_data)
        self.assertEqual(self.security_data, m)
        self.assertEqual(0, len(r.related_hostnames))
