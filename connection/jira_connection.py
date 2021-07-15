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
import logging
from typing import List, Dict, Optional
import jira
from requests.exceptions import ConnectionError
from jira import JIRA, JIRAError


class JiraConnection:
    """A utility class to query the Jira API"""

    def __init__(self, url: str, username: str, password: str, default_params: Dict[str, str], dry_run: bool = False):
        if not url:
            raise ValueError("JiraConnection: require URL")
        if not username:
            raise ValueError("JiraConnection: require username")
        if not password:
            raise ValueError("JiraConnection: require password")
        if not default_params:
            raise ValueError("JiraConnection: require default parameters")
        if 'project' not in default_params or not default_params['project']:
            raise ValueError("JiraConnection: require default Jira project name")
        if 'issuetype' not in default_params or not default_params['issuetype']:
            raise ValueError("JiraConnection: require default Jira issue type")
        if 'priority' not in default_params or not default_params['priority']:
            raise ValueError("JiraConnection: require default Jira issue priority")

        self.url = url
        self.username = username
        self.password = password
        self.default_params = default_params
        self.dry_run = dry_run

    def __enter__(self):
        self.__open_jira_connection()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__close_jira_connection()

    def __open_jira_connection(self):
        if self.dry_run:
            self.authed_jira = None
            return

        jira_options = {
            'server': self.url,
            # 'verify': 'the-certificate.cer'
        }

        try:
            self.authed_jira = JIRA(
                jira_options,
                basic_auth=(self.username, self.password),
                max_retries=0)
        except ConnectionError:
            raise ValueError("Cannot connect to Jira")
        except JIRAError:
            raise ValueError("Cannot connect to Jira - wrong credentials?")

    def __close_jira_connection(self):
        if self.authed_jira:
            self.authed_jira.close()

    def _get_params(self, params: Dict[str, Optional[str]]) -> Dict[str, str]:
        """Return a complete set of Jira parameters.
        If the provided parameters don't contain all required parameters, they're completed with default parameters.
        :param params: the Jira parameters
        :return: a complete set of Jira parameters with all required parameters set
        """
        new_params = self.default_params.copy()
        new_params.update({x: y for x, y in params.items() if y})
        return new_params

    def get_issue(self, issue_key) -> jira.Issue:
        return self.authed_jira.issue(issue_key)

    def add_comment(self, issue_id: str, comment: str) -> Optional[jira.Comment]:
        """Add a comment to a Jira issue.
        :param issue_id: the Jira issue ID
        :param comment: the comment to add
        :return: the comment that was added
        """
        if not comment:
            return
        if self.dry_run:
            logging.info(f"Dry-run -- would add comment to Jira issue {issue_id}: {comment}")
            return

        return self.authed_jira.add_comment(issue_id, comment)

    def get_issues_with_summary_prefix(self, prefix: str, params: Dict[str, str]) -> List[str]:
        params = self._get_params(params)
        if self.dry_run:
            logging.info(f"Dry-run -- would get issues with prefix {prefix} and params {params}")
            return []

        issues = self.authed_jira.search_issues(
            f"project={params['project']} AND "
            f"summary ~ '{prefix}'")

        hits = [x.key for x in issues if x.fields.summary.startswith(prefix)]
        return hits

    def create_issue(
            self,
            summary: str,
            description: str,
            params: Dict[str, str]) -> Optional[str]:
        """Create a new Jira issue.
        :param summary: the Jira issue summary
        :param description: the Jira issue description
        :param params: the Jira parameters to use; required parameters that are not provided are taken from this
        instance's default parameters.
        :except RuntimeError: if the Jira ticket could not be created
        :return: the Jira issue key of the newly created issue
        """
        params = self._get_params(params)

        fields = {
            'project': {'key': params['project']},
            'summary': summary,
            'description': description,
            'issuetype': {'name': params['issuetype']},
            'priority': {'name': params['priority']},
        }

        if 'label' in params and params['label']:
            fields['labels'] = [params['label']]

        if self.dry_run:
            logging.info(f"Dry-run -- would create Jira issue with fields: {fields}")
            return

        try:
            new_issue = self.authed_jira.create_issue(fields=fields)
        except JIRAError as e:
            raise RuntimeError(str(e))

        if 'assignee' in params and params['assignee']:
            self.authed_jira.assign_issue(new_issue, params['assignee'])

        return new_issue.key
