"""
Copyright 2021 Dynatrace LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from typing import Dict, Set
import copy
from rules.rule import Rule
from rules.operators import equals, equals_ignore_case, startswith, startswith_ignore_case, contains,\
    contains_ignore_case
from security_data import SecurityData


class AffectedEntityRule(Rule):
    """A rule that targets the names of Dynatrace affected entities.
    Note that this is designed to work generically for all types of affected entities.
    For example, while affected entities of Java library vulnerabilities are processes, Kubernetes vulnerabilities
    affect hosts. In both cases, the rule targets the entity name, independent of what type it is.
    """

    SUPPORTED_OPERATORS = {
        "startswith": startswith,
        "startswithIgnoreCase": startswith_ignore_case,
        "equals": equals,
        "equalsIgnoreCase": equals_ignore_case,
        "contains": contains,
        "containsIgnoreCase": contains_ignore_case,
    }

    def __init__(self, value: str, operator: str, minimum_score: float, stop_after_match: bool, params: Dict[str, str]):
        super(AffectedEntityRule, self).__init__(value, operator, minimum_score, stop_after_match, params)

    @property
    def supported_operators(self) -> Dict:
        return self.SUPPORTED_OPERATORS

    @property
    def target_attribute_name(self):
        return 'affected_entity_names'

    def _get_match_and_remainder(self, security_data: SecurityData, matching_entity_names: Set[str]):
        remainder = copy.deepcopy(security_data)
        security_data.remove_affected_entities_by_name(matching_entity_names, False)
        remainder.remove_affected_entities_by_name(matching_entity_names, True)
        return security_data, remainder
