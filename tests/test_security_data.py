from unittest import TestCase
from security_data import SecurityData, EntityDetails
from pydantic import ValidationError

GOOD_DATA = {
    "securityProblemId": "the_id",
    "displayId": "S-123",
    "title": "the_title",
    "url": "https://fake.example/the_id",
    "riskAssessment": {
        "riskScore": "9.2",
        "riskLevel": "high",
        "exposure": "foo",
        "dataAssets": "bar",
    },
    "description": "desc",
    "technology": "tech",
    "vulnerableComponents": [
        {
            "displayName": "foo",
        }
    ],
    "relatedEntities": {
        'hosts': [
            {
                "id": "the_host_id1",
                "affectedEntities": [
                    "the_process_id1"
                ]
            },
            {
                "id": "the_host_id2",
                "affectedEntities": [
                    "the_process_id2"
                ]
            },
        ]
    },
    "affectedEntities": ["the_process_id1", "the_process_id2"],
}


ALL_AFFECTED_ENTITIES = {
    "the_process_id1": EntityDetails(entityId="the_process_id1", displayName="the_process_name1",
                                     tags=[{'stringRepresentation': 'my_tag'}]),
    "the_process_id2": EntityDetails(entityId="the_process_id2", displayName="the_process_name2", tags=[]),
}
ALL_RELATED_HOST_ENTITIES = {
    "the_host_id1": EntityDetails(entityId="the_host_id1", displayName="the_host_name1", tags=[]),
    "the_host_id2": EntityDetails(entityId="the_host_id2", displayName="the_host_name2", tags=[])
}


class TestSecurityData(TestCase):
    def test_create_sunshine(self):
        try:
            SecurityData.create(GOOD_DATA, ALL_AFFECTED_ENTITIES, ALL_RELATED_HOST_ENTITIES)
        except ValidationError:
            self.fail("Validation error on good data")

    def test_create_fails_on_missing_data(self):
        good_data_as_list = list(GOOD_DATA.items())
        for index, t in enumerate(good_data_as_list):
            bad_data = dict(good_data_as_list[:index] + good_data_as_list[index+1:])
            self.assertRaises(ValueError, SecurityData.create, bad_data, ALL_AFFECTED_ENTITIES,
                              ALL_RELATED_HOST_ENTITIES)

    def test_create_invalid_input(self):
        self.assertRaises(ValueError, SecurityData.create, GOOD_DATA, ALL_AFFECTED_ENTITIES, {})
        self.assertRaises(ValueError, SecurityData.create, GOOD_DATA, {}, ALL_RELATED_HOST_ENTITIES)
        self.assertRaises(ValueError, SecurityData.create, {}, ALL_AFFECTED_ENTITIES, ALL_RELATED_HOST_ENTITIES)

    def test_remove_affected_entities_by_name(self):
        security_data = SecurityData.create(GOOD_DATA, ALL_AFFECTED_ENTITIES, ALL_RELATED_HOST_ENTITIES)
        self.assertListEqual(['the_process_name1', 'the_process_name2'], security_data.affected_entity_names)
        security_data.remove_affected_entities_by_name({'the_process_name1'}, remove_matches=True)
        self.assertListEqual(['the_process_name2'], security_data.affected_entity_names)
        security_data.remove_affected_entities_by_name({'the_process_name2'}, remove_matches=False)
        self.assertListEqual(['the_process_name2'], security_data.affected_entity_names)
        security_data.remove_affected_entities_by_name({'the_process_name1'}, remove_matches=False)
        self.assertEqual(0, len(security_data.affected_entity_names))

    def test_remove_affected_entities_by_tags(self):
        security_data = SecurityData.create(GOOD_DATA, ALL_AFFECTED_ENTITIES, ALL_RELATED_HOST_ENTITIES)
        self.assertListEqual(['the_process_name1', 'the_process_name2'], security_data.affected_entity_names)
        security_data.remove_affected_entities_by_tags({'my_tag'}, remove_matches=True)
        self.assertListEqual(['the_process_name2'], security_data.affected_entity_names)

    def test_remove_affected_entities_by_related_hostnames(self):
        security_data = SecurityData.create(GOOD_DATA, ALL_AFFECTED_ENTITIES, ALL_RELATED_HOST_ENTITIES)
        self.assertListEqual(['the_process_name1', 'the_process_name2'], security_data.affected_entity_names)
        self.assertListEqual(['the_host_name1', 'the_host_name2'], security_data.related_hostnames)

        security_data.remove_affected_entities_by_related_hostnames({'the_host_name1'}, remove_matches=True)
        self.assertListEqual(['the_process_name2'], security_data.affected_entity_names)
        self.assertListEqual(['the_host_name2'], security_data.related_hostnames)

        security_data.remove_affected_entities_by_related_hostnames({'the_host_name2'}, remove_matches=False)
        self.assertListEqual(['the_process_name2'], security_data.affected_entity_names)
        self.assertListEqual(['the_host_name2'], security_data.related_hostnames)

        security_data.remove_affected_entities_by_related_hostnames({'the_host_name1'}, remove_matches=False)
        self.assertEqual(0, len(security_data.affected_entity_names))
        self.assertEqual(0, len(security_data.related_hostnames))
