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
from __future__ import annotations
from typing import Set, Dict, Tuple, Optional
from abc import ABC, abstractmethod
from collections.abc import Iterable
import hashlib
from security_data import SecurityData


class Rule(ABC):
    """An abstract representation of a rule that can be matched with SecurityData.
    """

    TYPE_FIELD = 'type'

    @abstractmethod
    def __init__(self, value: str, operator: str, minimum_score: float, stop_after_match: bool, params: Dict[str, str]):

        if value is None:  # note: an empty value is allowed, this can be used for generic matches
            raise ValueError("Rule: value required")
        if not operator:
            raise ValueError("Rule: operator required")
        if minimum_score and (minimum_score < 0 or minimum_score > 10):
            raise ValueError("Rule: 0<=minimum_score<=10 required")
        if not params:
            raise ValueError(f"Rule: params required")
        if operator not in self.supported_operators:
            raise ValueError(f"Rule: operator not supported: {operator}")

        self.value = value
        self.operator = operator
        self.eval_function = self.supported_operators[operator]
        self.minimum_score = minimum_score
        self.stop_after_match = stop_after_match
        self.params = params

    @property
    @abstractmethod
    def supported_operators(self) -> Dict:
        """A dict mapping the operator names (e.g., 'startswith') to a function implementing this operator
        (e.g., operators.startswith).
        """
        pass

    @property
    @abstractmethod
    def target_attribute_name(self) -> str:
        """The name of SecurityData attribute on which a specific rule is operating on.
        For example: if a rule is meant to analyze the names of entities that are affected by a vulnerability, then the
        target attribute name should be 'affected_entities'. See :class:`SecurityData <SecurityData>`.
        :return: just the attribute name, without a class prefix or anything else
        """
        pass

    @abstractmethod
    def _get_match_and_remainder(
            self,
            security_data: SecurityData,
            matches: Set[str]) -> Tuple[SecurityData, SecurityData]:
        """See :func:`match <Rule.match>`. The mechanics of the actual splitting in match and remainder are specific
        to each individual Rule and need to be implemented there.
        :param security_data: the SecurityData to split in match and remainder
        :param matches: the exact matches that were found in SecurityData.<target_attribute_name>. I.e., if the rules
        target_attribute_name is 'affected_entities' then this would be the list of names of affected entities that
        are matching the rule.
        :return: a tuple (match, remainder) where match contains the matching portion of security_data and remainder
        contains the remaining portion.
        """
        pass

    def __str__(self):
        return f"Rule: {self.eval_function.__name__} {self.value}"

    @property
    def hex_id(self) -> str:
        """A unique identifier for this rule, based on the class name, the <operator>, the <value> and the
        <stop_after_match> attributes.
        :return: a hex string with length == 6
        """
        h = hashlib.md5()
        h.update(self.__class__.__name__.encode('utf-8'))
        h.update(self.operator.encode('utf-8'))
        h.update(self.value.encode('utf-8'))
        h.update(str(self.minimum_score).encode('utf-8'))
        h.update(str(self.stop_after_match).encode('utf-8'))
        return h.hexdigest()[:6]

    def match(self, security_data: SecurityData) -> Tuple[Optional[SecurityData], Optional[SecurityData]]:
        """Match some SecurityData with this rule.
        Rules support partial matches. Whenever a rule matches, this function updates the original security_data
        to contain only the matching portion and returns a second (copied) SecurityData that holds the remaining, not
        matching portion.
        For example: if a vulnerability affects entities X and Y and a rule matches only X, then the returned match
        will contain X only and the returned remainder will contain Y only.
        :param security_data: the SecurityData to split in match and remainder
        :return: a tuple (match, remainder) where match contains the matching portion of security_data and remainder
        contains the remaining portion. Both may be null, in case there is either no match or there is nothing left as
        everything was matched.
        """

        if security_data is None:
            return None, None

        if self.minimum_score and security_data.risk_score < self.minimum_score:
            return None, security_data

        # need target attribute, to be defined by child class
        target_attribute_values = getattr(security_data, self.target_attribute_name)

        # the target attribute can point at an Iterable (List, Set, ..) or at a single value
        if (isinstance(target_attribute_values, Iterable)
           and not isinstance(target_attribute_values, (str, bytes, bytearray))):
            matches = {x: self.eval_function(x, self.value) for x in target_attribute_values}
        else:
            matches = {self.eval_function(target_attribute_values, self.value)}

        if not any(matches.values()):
            return None, security_data

        # There's at least one match and this rule says that we should stop after a match.
        # Return the entire security_data, not just the matching part.
        if self.stop_after_match:
            return security_data, None

        return self._get_match_and_remainder(security_data, set([k for k, v in matches.items() if v]))

    @staticmethod
    def create(rule: Dict[str]) -> Rule:
        """A factory method to create a new Rule.
        :param rule: the dict containing the rule description
        :except ValueError: if an invalid rule description was provided
        :return: a new Rule
        """
        from rules.hostname_rule import HostnameRule
        from rules.affected_entity_rule import AffectedEntityRule
        from rules.affected_entity_tag_rule import AffectedEntityTagRule

        supported_rule_types = {
            "hostname": HostnameRule,
            "affectedEntity": AffectedEntityRule,
            "affectedEntityTag": AffectedEntityTagRule,
        }

        if Rule.TYPE_FIELD not in rule:
            raise ValueError("Rule: need type to create rule")
        if rule[Rule.TYPE_FIELD] not in supported_rule_types:
            raise ValueError(f"Rule: unsupported type: {rule[Rule.TYPE_FIELD]}")
        if any([x not in rule for x in ("value", "operator", "params")]):
            raise ValueError("Rule: need value, operator, params")
        minimum_score = rule['minimumScore'] if 'minimumScore' in rule else None
        stop_after_match = rule['stopAfterMatch'] if 'stopAfterMatch' in rule else False

        return supported_rule_types[rule[Rule.TYPE_FIELD]](rule['value'],
                                                           rule['operator'],
                                                           minimum_score,
                                                           stop_after_match,
                                                           rule['params'])
