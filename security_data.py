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
import weakref
import copy
from typing import Set, Dict, List
import itertools
from pydantic import BaseModel, validator, confloat, AnyHttpUrl
from connection.dynatrace_connection import EntityDetails


class AffectedEntity:
    """Data model for affected entities.
    E.g., vulnerable processes or vulnerable hosts, depending on the type of vulnerability.
    """
    def __init__(self, entity_id: str, entity_name: str, tags: List[Dict]):
        self.entity_id = entity_id
        self.entity_name = entity_name
        self.tags = tags


class RelatedEntity:
    """Data model for related entities.
    E.g., services or hosts that relate to particular affected entities
    This class store weak references to affected entities."""
    def __init__(self, entity_id: str, entity_name: str, affected_entities: List[AffectedEntity]):
        self.entity_id = entity_id
        self.entity_name = entity_name
        self.affected_entities = weakref.WeakSet(affected_entities)

    def __deepcopy__(self, memo):
        """Make sure that deep copies work correctly.
        As new instances of AffectedEntities are created, the weak references need to point to them.
        If we wouldn't do that, the weak references would still point to the original instances.
        :param memo: see See :func:`deepcopy <copy.deepcopy>`
        :return: see See :func:`deepcopy <copy.deepcopy>`
        """
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        for k, v in self.__dict__.items():
            if isinstance(v, weakref.WeakSet):
                new_v = weakref.WeakSet([copy.deepcopy(x.__repr__.__self__, memo) for x in v])
            else:
                new_v = copy.deepcopy(v, memo)
            setattr(result, k, new_v)
        return result


class SecurityData(BaseModel):
    """Model to hold *all* required data that relates to a single Dynatrace Security Problem.
    A subset of the actual Security Problem information as provided by the Dynatrace Security Problem API is
    contained here and is extended with additional information as, e.g., the hostnames where affected processes are
    running."""
    identifier: str
    display_id: str
    title: str
    url: AnyHttpUrl
    risk_score: confloat(ge=0, le=10)
    risk_level: str
    exposure: str
    data_assets: str
    technology: str
    description: str
    vulnerable_components: Set[str]
    affected_entities: Dict[str, AffectedEntity]
    related_hosts: List[RelatedEntity]

    @validator('risk_level', 'technology', 'exposure', 'data_assets', pre=True)
    def enforce_uppercase(cls, v):
        return v.upper()

    class Config:
        # don't enforce checks on the contained custom types (e.g., AffectedEntity)
        arbitrary_types_allowed = True

    @property
    def affected_entity_names(self):
        """The names of the Dynatrace entities that are affected by this vulnerability"""
        return [x.entity_name for x in self.affected_entities.values()]

    @property
    def affected_entity_tags(self):
        """The string representations of the tags of all affected entities"""
        return {t['stringRepresentation'] for x in self.affected_entities.values() for t in x.tags}

    @property
    def related_hostnames(self):
        """The names of the hosts that are related to this vulnerability"""
        return [x.entity_name for x in self.related_hosts if len(x.affected_entities)]

    def remove_affected_entities_by_name(self, entity_names: Set[str], remove_matches: bool):
        """Remove all affected entities that match the specified entity_names.
        Note: this automatically implies that these entities are also removed from internally stored related entities.
        For example: assume that only entity X is affected and X relates to host H. As soon as X gets removed also the
        reverse link will work as expected: getting all affected entities that run on host H will yield an empty list
        in this case.
        :param entity_names: the names of the affected entities to remove
        :param remove_matches: if True, remove all matches. if False, remove all non-matches.
        """
        entity_ids = {x.entity_id for x in self.affected_entities.values() if x.entity_name in entity_names}

        if remove_matches:
            entity_ids_to_delete = entity_ids
        else:
            entity_ids_to_delete = set(self.affected_entities.keys()) - entity_ids

        for x in entity_ids_to_delete:
            del self.affected_entities[x]

    def remove_affected_entities_by_tags(self, entity_tags: Set[str], remove_matches: bool):
        """Remove all affected entities that got any of the provided entity tags.
        :param entity_tags: the entity tags
        :param remove_matches: if True, remove all matches. if False, remove all non-matches.
        """
        entity_ids = set()
        for ae in self.affected_entities.values():
            # fixme: ensure that stringRepresentation field exists
            tags = [x['stringRepresentation'] for x in ae.tags]
            if any([x in tags for x in entity_tags]):
                entity_ids.add(ae.entity_id)

        if remove_matches:
            entity_ids_to_delete = entity_ids
        else:
            entity_ids_to_delete = set(self.affected_entities.keys()) - entity_ids

        for x in entity_ids_to_delete:
            del self.affected_entities[x]

    def __remove_affected_entities_by_related_entity_name(
            self,
            entity_names: Set[str],
            remove_matches: bool,
            attribute: List[RelatedEntity]
    ):
        """RelatedEntity objects store weak references to AffectedEntity objects internally.
        In general, many RelatedEntity objects point to the same AffectedEntity objects.
        This helper method removes all affected entities where the entity name of a re
        :param entity_names: the entity names
        :param remove_matches: if True, remove all matches. if False, remove all non-matches.
        :param attribute: the class attribute to operate on
        """
        affected_entity_ids = set(itertools.chain([affected_entity.entity_id
                                                   for related_host in attribute
                                                   for affected_entity in related_host.affected_entities
                                                   if related_host.entity_name in entity_names]))
        if remove_matches:
            affected_entity_ids_to_remove = affected_entity_ids
        else:
            affected_entity_ids_to_remove = {x for x in self.affected_entities.keys() if x not in affected_entity_ids}

        # NOTE: we delete from the the list of *affected* entities,
        # leveraging the WeakSet in RelatedEntity and keeping everything in sync
        for x in affected_entity_ids_to_remove:
            del self.affected_entities[x]

    def remove_affected_entities_by_related_hostnames(self, hostnames: Set[str], remove_matches: bool):
        """
        Remove all affected entities that relate to the specified hostnames.
        For example: assume that only entity X is affected and X relates to host H. As soon as H gets removed all
        affected entities relating to H (in this case, X) also get removed.
        :param hostnames: the hostnames to remove
        :param remove_matches: if True, remove all matches. if False, remove all non-matches.
        """
        self.__remove_affected_entities_by_related_entity_name(hostnames, remove_matches, self.related_hosts)
        self.related_hosts = [x for x in self.related_hosts if x.affected_entities]

    @staticmethod
    def create(
            security_problem: Dict,
            all_affected_entities: Dict[str, EntityDetails],
            all_related_hosts: Dict[str, EntityDetails]
    ) -> SecurityData:
        """
        Create a SecurityData instance.
        :param security_problem: the security problem data
        :param all_affected_entities: a dict containing entity IDs and EntityDetails. Generally consider this a lookup
        table that contains more data than what's needed for this security problem. It must contain everything that's
        needed, but may contain more than that.
        :param all_related_hosts: a dict containing entity IDs and EntityDetails. Generally consider this a lookup
        table that contains more data than what's needed for this security problem. It must contain everything that's
        needed, but may contain more than that.
        :return: a SecurityData instance
        :except ValueError if required data was not found in input data
        :except ValidationError if provided data could not be validated
        """
        try:
            affected_entities = [AffectedEntity(
                                    entity_id=all_affected_entities[x].entity_id,
                                    entity_name=all_affected_entities[x].entity_name,
                                    tags=all_affected_entities[x].tags)
                                 for x in security_problem['affectedEntities']]

            # Note that we're here creating weak refs to the affected entities that we just created
            related_hosts = [RelatedEntity(
                                    entity_id=all_related_hosts[x['id']].entity_id,
                                    entity_name=all_related_hosts[x['id']].entity_name,
                                    affected_entities=[z for z in affected_entities
                                                       if z.entity_id in x['affectedEntities']])
                             for x in security_problem['relatedEntities']['hosts']]

            data = {
                "identifier": security_problem['securityProblemId'],
                "display_id": security_problem['displayId'],
                "title": security_problem['title'],
                "url": security_problem['url'],
                "risk_score": security_problem['riskAssessment']['riskScore'],
                "risk_level": security_problem['riskAssessment']['riskLevel'],
                "exposure": security_problem['riskAssessment']['exposure'],
                "data_assets": security_problem['riskAssessment']['dataAssets'],
                "description": security_problem['description'],
                "technology": security_problem['technology'],
                "vulnerable_components": set([x['displayName'] for x in security_problem['vulnerableComponents']]),
                "affected_entities": {x.entity_id: x for x in affected_entities},
                "related_hosts": related_hosts,
            }
        except KeyError as ex:
            raise ValueError(f"SecurityData: missing data; {str(ex)}")
        else:
            return SecurityData(**data)
