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
from typing import List, Dict, Optional
from pydantic import BaseModel, validator

CONFIG_SECTION_DT = "dt_conn"
CONFIG_SECTION_JIRA = "jira_conn"
CONFIG_SECTION_JIRA_DEFAULTS = "jira_defaults"
CONFIG_SECTION_RULES = "rules"


class Config(BaseModel):
    dt_conn: Dict[str, str]
    jira_conn: Dict[str, str]
    rules: List[Optional[Dict]]
    jira_defaults: Dict[str, str]
    ignore_rest: Optional[bool] = False

    @validator('dt_conn')
    def dynatrace_parameters_present(cls, v):
        if 'url' not in v:
            raise ValueError("Dynatrace URL missing")
        if 'token' not in v:
            raise ValueError("Dynatrace token missing")

        # automatically append /api/v2/ to URL if missing
        url = v['url']
        if url.endswith('/api/v2') or url.endswith('/api/v2/'):
            return v
        if url.endswith('/'):
            url += 'api/v2/'
        else:
            url += '/api/v2/'
        v['url'] = url
        return v

    @validator('jira_conn')
    def jira_parameters_present(cls, v):
        if 'url' not in v:
            raise ValueError("Jira URL missing")
        if 'username' not in v:
            raise ValueError("Jira username missing")
        if 'password' not in v:
            raise ValueError("Jira password missing")
        return v

    @validator('rules', each_item=True)
    def rules_format_is_correct(cls, v):
        if 'type' not in v:
            raise ValueError("Rule type missing")
        if 'value' not in v:
            raise ValueError("Rule value missing")
        if 'operator' not in v:
            raise ValueError("Rule operator missing")
        if 'params' not in v:
            raise ValueError("Rule params missing")
        return v

    @validator('jira_defaults')
    def jira_required_defaults_present(cls, v):
        if 'project' not in v:
            raise ValueError("Default Jira project missing")
        if 'priority' not in v:
            raise ValueError("Default Jira priority missing")
        if 'issuetype' not in v:
            raise ValueError("Default Jira issue type missing")
        return v
