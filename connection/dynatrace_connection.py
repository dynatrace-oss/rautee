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
from typing import Dict, List, Optional
import requests
import logging
from urllib.parse import urljoin
from pydantic import BaseModel, Field


class EntityDetails(BaseModel):
    entity_id: str = Field(alias="entityId")
    entity_name: str = Field(alias="displayName")
    tags: List[Dict]


class DynatraceConnection:
    """A utility class to query the Dynatrace API"""

    def __init__(self, url: str, token: str):
        if not url:
            raise ValueError("DynatraceConnection: require URL")
        if not token:
            raise ValueError("DynatraceConnection: require token")

        # urljoin below needs a trailing slash, otherwise it doesn't work as expected
        self.url = url if url.endswith('/') else url + '/'
        self.token = token

    def __query(self, endpoint: str, params: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Query the Dynatrace API.
        :param endpoint: the endpoint to query
        :param params: the query parameters
        :except ValueError if a connection error occurred or if the HTTP response code was anything but 200
        :return: a dict representing the JSON response
        """
        headers_dict = {
            "Authorization": f"Api-Token {self.token}",
        }

        url = urljoin(self.url, endpoint)

        try:
            response = requests.get(url, headers=headers_dict, params=params)
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException):
            raise ValueError(f"Request failed: {url}")

        if response.status_code != 200:
            raise ValueError("Request failed. Wrong token?")

        return response.json()

    def get_open_security_problems(self) -> List[Dict[str, str]]:
        """
        Get all open security problems and their details.
        This supports pagination, i.e., when partial results are returned, the next pages are automatically
        fetched and are appended to the results.
        :except ValueError if the number of retrieved security problems doesn't match the expected total count
        :return: a list of dicts where each dict holds one security problem's details
        """

        params = {
            "securityProblemSelector": 'status("OPEN")',
        }

        results = []
        while True:
            security_problems = self.__query("securityProblems", params)
            logging.info(f"Dynatrace holds {security_problems['totalCount']} security problems")
            for sp in security_problems['securityProblems']:
                r = self.__query(
                    f"securityProblems/{sp['securityProblemId']}",
                    {"fields": "+riskAssessment,+relatedEntities,+affectedEntities,+description,+vulnerableComponents"}
                )
                results.append(r)

            next_page_key = security_problems.get('nextPageKey')
            if next_page_key:
                params = {"nextPageKey": next_page_key}
            else:
                break

        # sanity check
        if len(results) != security_problems['totalCount']:
            raise ValueError(f"Expected {security_problems['totalCount']} security problems, got {len(results)}")

        return results

    def get_entity_details(self, entity_ids: List[str]) -> Dict[str, EntityDetails]:
        """Issue a separate request to the API for each provided entity ID and fetch the entity details.
        :param entity_ids: the list of entity IDs
        :except ValidationError: if API response doesn't meet expectations
        :return: a dict that maps entity IDs to EntityDetails instances"""
        entity_details_dict = dict()
        for entity_id in entity_ids:
            d = self.__query(f"entities/{entity_id}", {"fields": "+tags"})
            entity_details_dict[entity_id] = EntityDetails(**d)
        return entity_details_dict

    def get_hostnames(self, host_ids: List[str]) -> Dict[str, str]:
        """
        Get all host names for the provided list of host IDs
        :param host_ids: the host IDs for which to lookup the host names
        :return: a dict mapping host IDs to host names
        """
        hosts = []
        for host_id in host_ids:
            hosts.append(self.__query(f"entities/{host_id}", None))
        return {h['entityId']: h['displayName'] for h in hosts}

    def get_process_names(self, process_ids: List[str]) -> Dict[str, str]:
        """
        Get all process names for the provided list of process IDs
        :param process_ids: the process IDs for which to lookup the process names
        :return: a dict mapping host IDs to process names
        """
        processes = []
        for process_id in process_ids:
            processes.append(self.__query(f"entities/{process_id}", None))
        return {h['entityId']: h['displayName'] for h in processes}
