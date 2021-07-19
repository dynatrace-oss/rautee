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
import json
import logging
import sys
from textwrap import dedent
from typing import Dict, List, Set
from pydantic import ValidationError
from config import Config
from security_data import SecurityData
from rules.rule import Rule
from connection.jira_connection import JiraConnection
from connection.dynatrace_connection import DynatraceConnection


def get_unique_affected_entity_ids(security_problems: List[Dict]) -> Set[str]:
    """Extract all unique affected entity IDs from a list of security problems.
    :param security_problems: the security problems, parsed from JSON to Dicts of Dicts
    :return: the set of unique affected entity IDs across all provided security problems
    """
    if not all(['affectedEntities' in x for x in security_problems]):
        raise ValueError("Security problems need to contain attribute 'affectedEntities'")
    return {entry for sp in security_problems for entry in sp['affectedEntities']}


def get_unique_related_host_ids(security_problems: List[Dict]) -> Set[str]:
    """Extract all unique related host IDs from a list of security problems.
    :param security_problems: the security problems, parsed from JSON to Dicts of Dicts
    :return: the set of unique related host IDs across all provided security problems
    """
    if not all(['relatedEntities' in x for x in security_problems]):
        raise ValueError("Security problems need to contain 'relatedEntities'")
    if not all(['hosts' in x['relatedEntities'] for x in security_problems]):
        raise ValueError("Security problems need to contain 'relatedEntities'->'hosts'")
    if not all(['affectedEntities' in y for x in security_problems for y in x['relatedEntities']['hosts']]):
        raise ValueError("Security problems need to contain 'relatedEntities'->'hosts'->'affectedEntities'")
    return {entry['id'] for sp in security_problems for entry in sp['relatedEntities']['hosts']}


def get_dynatrace_security_data(conn: DynatraceConnection) -> List[SecurityData]:
    """Get all data from Dynatrace that's required to open Jira tickets.
    That includes not only the security problems themselves, but also further information on, e.g., names of hostnames
    related to a particular problem.
    :param conn: the DynatraceConnection handle
    :except ValueError
    :except ValidationError
    :return: a list of SecurityData instances
    """
    security_problems = conn.get_open_security_problems()

    # query *all* hostnames and *all* PG names across all security problems
    # why: doesn't make sense to do this repeatedly for each security problem, typically we'd do duplicate work
    unique_affected_entity_ids = get_unique_affected_entity_ids(security_problems)
    unique_related_host_ids = get_unique_related_host_ids(security_problems)

    # we got all unique entities across all security problems, let's fetch the details for all of them
    all_affected_entities = conn.get_entity_details(list(unique_affected_entity_ids))
    all_related_hosts = conn.get_entity_details(list(unique_related_host_ids))

    # combine all data; for each security problem, we create an extended SecurityData object
    security_data_list = [SecurityData.create(x, all_affected_entities, all_related_hosts) for x in security_problems]

    return security_data_list


def create_affected_entities_description(security_data: SecurityData, limit: int = 5) -> str:
    """Create a description of the entities which are affected by a security problem.
    :param security_data: the security details for which to create the description
    :param limit: the maximum number of entities to list in the description
    :return: the description
    """
    def _stringify(entity_list: Set[str], label: str, the_limit: int):
        if len(entity_list) > the_limit:
            return f"{len(entity_list)} {label} affected ([details|{security_data.url}])\n"
        return f"Affected {label}: {', '.join(entity_list)}\n"

    desc = _stringify(security_data.affected_entity_names, 'entities', limit)
    desc += _stringify(security_data.related_hostnames, 'hostnames', limit)
    return desc


def create_issue_description(security_data: SecurityData) -> str:
    """Create the Jira issue description.
    :param security_data: the security details for which to create the description
    :return: a Markdown string"""
    desc = dedent(f"""

        *{security_data.risk_level} risk, score={security_data.risk_score}*
        Exposure: {security_data.exposure}
        Data assets: {security_data.data_assets}
        [See details in Dynatrace | {security_data.url}]

        *What's the problem:*
        {security_data.description}


        *What's affected:*

    """).strip()

    desc += "\n"
    desc += create_affected_entities_description(security_data, limit=5)
    return desc


def write_to_jira(security_data: SecurityData,
                  prefix: str,
                  params: dict,
                  jira_conn: JiraConnection,
                  add_comments: bool):
    """Write SecurityData information to Jira.
    Creates a new Jira issue if no issue this summary prefix already exists.
    If such an issue exists and add_comments=True, add a comment to the existing ticket.
    :param security_data: the security details to write to Jira
    :param prefix: the Jira issue summary prefix to check for and to use for newly created tickets
    :param params: the Jira parameters to use. Can be empty.
    :param jira_conn: the Jira connection handle
    :param add_comments: if True, add comments to existing Jira issue.
    """
    issue_keys = jira_conn.get_issues_with_summary_prefix(prefix, params)
    if issue_keys:
        logging.info(f"Jira issue exists: {security_data.identifier}, params={params}")

        if len(issue_keys) == 1 and add_comments \
            and jira_conn.add_comment(issue_keys[0],
                                     f"*Issue still exists - what's affected:*\n"
                                     f"{create_affected_entities_description(security_data, limit=50)}"):
                logging.info(f"Added comment to Jira issue {issue_keys[0]}")
    else:
        summary = f"{prefix} {security_data.title}"
        description = create_issue_description(security_data)
        jira_issue_key = jira_conn.create_issue(summary, description, params)
        if jira_issue_key:
            logging.info(f"Created new Jira issue {jira_issue_key} for {security_data.identifier}, params={params}")


def main(config: Config, dt_conn: DynatraceConnection, add_comments: bool = True, dry_run: bool = False):
    """Fetch Dynatrace security problem information and create Jira tickets.
    The rules provided in the config are evaluated and the Jira parameters are applied accordingly.
    The rules are processed in the order in which they are provided in the config. Whenever a rule matches,
    a Jira ticket is created for this portion of the security problem information. The remainder of the
    security problem information is processed further by the following rules. This stops when either there's no
    further information available or when there are no more rules. In the latter case, a Jira ticket for the
    remainder is created, using the provided Jira default parameters.

    For example:
    Security problem X relates to hostnames <foo> and <bar>.
    A rule exists for all hostnames that equal <foo>.
    When the rule matches, a Jira ticket is created for <foo>. <foo> is removed from the list of hostnames.
    Additionally, all affected entities that relate to <foo> are removed as well.
    The remainder of the security problem is processed further, but no other rule matches.
    A Jira ticket is created for <bar> and all remaining affected entities, using the provided Jira default parameters.
    :param config: the configuration
    :param dt_conn: the DynatraceConnection handle
    :param add_comments: if true, add comments to existing Jira issues that correspond to security problems. The idea is
    to write the current status of the security problem to Jira whenever this tool runs.
    :param dry_run: don't actually read/write from/to Jira. Just fetch all security problems, apply the configured
    rules, and write to the log what Jira actions would get triggered.
    """
    rules = [Rule.create(x) for x in config.rules]

    if config.ignore_rest and not rules:
        logging.error("No rules configured and default action is to ignore everything that's not matching a rule. "
                      "Aborting - that doesn't make sense.")
        sys.exit(-1)

    try:
        security_data_list = get_dynatrace_security_data(dt_conn)
    except ValidationError as ex:
        logging.error(str(ex))
        logging.error("Aborting - unexpected data received from Dynatrace API")
        sys.exit(-1)
    except ValueError as ex:
        logging.error(str(ex))
        logging.error("Aborting - unexpected response from Dynatrace API: are you using a wrong URL?")
        sys.exit(-1)

    with JiraConnection(config.jira_conn['url'],
                        config.jira_conn['username'],
                        config.jira_conn['password'],
                        config.jira_defaults,
                        dry_run=dry_run) as jira_conn:
        for sd in security_data_list:
            for rule in rules:
                match, remainder = rule.match(sd)

                if match:
                    logging.info(f"Rule matches: {rule}")
                    prefix = f"Dynatrace issue {sd.display_id}-{rule.hex_id}:"
                    write_to_jira(sd, prefix, rule.params, jira_conn, add_comments=add_comments)

                sd = remainder

            if sd and sd.affected_entities:
                if config.ignore_rest:
                    logging.info(f"Dynatrace issue {sd.display_id}: ignoring remaining data, as specified in config")
                else:
                    prefix = f"Dynatrace issue {sd.display_id}-0:"
                    write_to_jira(sd, prefix, {}, jira_conn, add_comments=add_comments)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    import argparse
    parser = argparse.ArgumentParser(description='Create Jira tickets from Dynatrace security findings')
    parser.add_argument('config_filename', metavar='config', type=str,
                        help='the config file to use')
    parser.add_argument('--dryrun', dest='dry_run', action='store_true', default=False,
                        help="Don't actually read/write from/to Jira")
    parser.add_argument('--comment', dest='add_comments', action='store_true', default=False,
                        help="Add comments to existing Jira issues")

    args = parser.parse_args()

    try:
        with open(args.config_filename) as f:
            config_dict = json.load(f)
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {args.config_filename}")
        sys.exit(-1)

    config = Config(**config_dict)
    dt_conn = DynatraceConnection(config.dt_conn['url'], config.dt_conn['token'])

    main(config, dt_conn, add_comments=args.add_comments, dry_run=args.dry_run)
