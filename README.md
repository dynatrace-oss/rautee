# Rautee

Detection and prioritization of security issues is not enough - route all issue details and runtime context directly
to the developers!

## What does this do?

  * Connect to the Dynatrace API to get detailed information on vulnerabilities and all the runtime context information
    you need
  * Create Jira tickets for these vulnerabilities that contain everything the developer needs to know
  * Apply custom rules to route the tickets to the right teams and automatically apply custom labels

![](img/overview.svg?raw=true)

## Why did you build this?

We believe that efficient DevSecOps automation requires custom logic.
On top of finding security issues themselves, Dynatrace provides a wealth of information that your team can use to
speed up their workflows. This tool connects Dynatrace with Jira, yet any other workflow tooling with an API could be
connected as well.

So here's what you can use this for:
  * If this does already all you need, go ahead and use it right away!
  * Missing something? Do you want another type of rule? Want to connect to anything else than Jira?
    Feel free to extend this code, we're happy to accept pull requests!
  * Don't think that's the right tool for you? Do you have a generic workflow engine that you'd rather use? Learn from
this code how you could use the Dynatrace API to build the integration on the platform that fits your needs!

# Getting started
1. Edit `config.sample.json` and save it as `config.json`.
2. Adjust the configuration to your needs (see below).
3. Run the tool directly or pass the arguments to our Docker container.

```shell
python main.py --dryrun config/config.json
```

Note that Python >= 3.5 is required. You will also need to install some dependencies by executing `pip install -r requirements.txt`.

```shell
docker build -t rautee .
docker run -it --rm \
  -v /full/path/to/config:/config \
  rautee --dryrun /config/config.json
```

The `--dryrun` parameter causes the tool to not do any actual changes to Jira but simply write logs saying what would be
done. That means that you can safely play around with the configuration settings. Run it without `--dryrun` as soon as
you're ready to write to Jira.

## Command line options
* `--comment`: tickets for a specific issue might already exist when this tool is run multiple times (see FAQ below).
When this option is set, every time the tool runs, a comment is added to the Jira ticket that contains up-to-date
information on the current runtime impact of this vulnerability.
* `--dryrun`: don't require a connection to Jira. Simply output what Jira actions would have been triggered.

## Dynatrace configuration
You need to provide the URL of the Dynatrace API of your environment + an [API token](https://www.dynatrace.com/support/help/dynatrace-api/basics/dynatrace-api-authentication/).
Make sure that your API token is created with (at least) `Read security problems` and `Read entities` permissions.

## Jira configuration
You need to provide the Jira URL + username + password.
Furthermore, you need to provide Jira default parameters. These parameters will be used if either no specific rule 
matched (see below) or if the rule doesn't specify all required Jira parameters. 
You need to specify the Jira project name, the issue type (e.g., "Bug") and the ticket priority (e.g., "HIGH").
You can optionally also provide an assignee and a label that you want to apply to the created Jira tickets.

## Rules
A key idea of this tool is to support "Rules". A Rule is a description of which Jira parameters should be used to create
a ticket, depending on the properties of the Dynatrace security problem.

The following types of rules are currently supported:
* *AffectedEntity*: targets names of entities that are affected by a security problem. Often, this corresponds to
process names that, e.g., load a vulnerable library. However, in case of Kubernetes vulnerabilities, the affected
  entities are Kubernetes nodes.
* *AffectedEntityTag*: targets the tags written onto affected entities. Specifically, it targets the
  `stringRepresentation` field as returned by the [Dynatrace API](https://www.dynatrace.com/support/help/dynatrace-api/environment-api/entity-v2/get-entity/).
* *Hostname*: targets names of hosts that are related to a security problem. E.g., host X is related to security problem
  Y if a process that's affected by Y runs on X.
  
The following table shows an overview of the supported rule types and which operators (e.g., `startswith`)
are supported for them:

| Rule type | _startswith_ | _startswithIgnoreCase_  |_equals_ | _equalsIgnoreCase_ | _contains_ | _containsIgnoreCase_
|---------- | ------------ | ----------------------- | ------- | ------------------ | ---------- | ------------------- |
| AffectedEntity   | [x] | [x] | [x] | [x] | [x] | [x] |
| AffectedEntityTag   | [x] | [x] | [x] | [x] | [x] | [x] |
| Hostname  | [x] | [x] | [x] | [x] | [x] | [x] |

See the examples in `config.sample.json`, it's simple to get started!

# I want more details on how this works!

Sure! Let's start with an example.

Let's assume your environment and your requirements are as follows: 
`process-1` is your most important service, whenever something happens to it the ticket should immediately get assigned
to John Smith. `host-X` is part of a larger set of hosts that all start with the same prefix.
They host your production environment. All issues that are raised there and that have a score higher than 8.0 
should end up in the security team's Jira project and get the label "security_emergency".

All remaining issues should also trigger "Bug" tickets in your default Jira project with priority "High".

This is how you would do that:

```json
  "jira_defaults": {
    "project": "DefaultProject",
    "priority": "High",
    "issuetype": "Bug"
  }, 
  "rules": [
    {
      "type": "affectedEntity",
      "value": "process-1",
      "operator": "equals",
      "params": {
          "assignee": "John Smith"
      },
    },
    {
      "type": "hostname",
      "value": "host-",
      "operator": "startswith",
      "minimumScore": 8.0,
      "params": {
          "project": "Security",
          "label": "security_emergency"
      }
    },
    "ignore_rest": false
]
```

Assume that Dynatrace raised a security problem for a new Java vulnerability with score=10.0 and figured out that it
affects processes `process-1` and `process-2`. Furthermore, Dynatrace automatically adds information on where these
processes are running. In our example, `process-1` is running on `host-X` and  `process-2` is running on `host-Y`.

With the config above in place, the following will happen as soon as the example vulnerability gets detected:
1. A Jira ticket for John Smith gets created and gets assigned to John Smith, referencing `process-1` and `host-X`.
2. Another Jira ticket gets created in the "Security" project, referencing `process-2` and `host-Y`.
3. No further tickets are created as all affected entities (`process-1` and `process-2`) are tracked by Jira
tickets by now.
   
## I want a rule to match only if the security incident has a certain minimum severity
Just specify `minimumScore: <your-threshold>` where the threshold needs to be a number between zero and 10.
See the [Dynatrace API documentation](https://www.dynatrace.com/support/help/dynatrace-api/environment-api/security-problems/get-problem/)
for details on the risk scores provided by Dynatrace.

## I don't want to continue after one rule matched
Just set `"stopAfterMatch": true` for a rule. See below for more details.
There's an example in `config.sample.json`.

## I want to match only on the score, not on any other property
Use, e.g., a `HostnameRule` with a `contains` operator and an empty `value`. Specify a `minimumScore` condition there.
There's an example in `config.sample.json`.

## What happens if there are still affected processes after processing all rules for a specific vulnerability?
Another Jira ticket is created using the Jira parameters configured in `jira_defaults`. The ticket will contain all
remaining details regarding entities that were not matched by any rule.

## I don't want this - can I simply ignore what remains after matching all rules?
Sure. Just set `"ignore_rest": true`. There's an example in `config.sample.json`. Be aware that you're then deliberately
ignoring vulnerable entities in your environment.

## How are rules processed
Rules operate on what we call `SecurityData` in the code. Each instance of `SecurityData` represents a single security
issue and contains additional information on the runtime entities (processes, hosts, ...) that are affected.
Rules are processed in the order in which they're listed in the `config.json` file.
Whenever a rule matches some `SecurityData`, a Jira ticket is created using the Jira parameters provided with the rule
in `config.json`. If a required Jira parameter is not provided with a specific rule, the missing parameter is taken from
the top-level `jira_defaults` section in `config.json`.

The matching affected entities (e.g., the processes matching a certain rule) are removed from the `SecurityData`
instance and the remaining data gets further processed. Ultimately, another Jira ticket gets created for whatever is
left after processing all rules.

The behavior changes if a rule has `stopAfterMatch: true`. In this case, a Jira ticket is created for the entire
`SecurityData` that made it to this rule. There is no remainder that's further processed.

# Workflow integrations? What's so special about that - it's straight-forward!

We disagree :)
It's fairly simple to create tickets from whatever product out there. However, manually triaging these tickets
doesn't quite work in larger organizations. Therefore, these tickets get handled too late, typically end up at the wrong
person, with too little context to make them actionable. That means that they get re-assigned, commented-on, discussed
in meetings ... in short, they are often not handled within adequate time and cause lots of manual effort by multiple
people before anything happens.

Sounds familiar? We think that's a waste. Dynatrace knows exactly what runs where, what the topology of the running
application is, what traffic is currently seen and much more. All the information that's needed to decide in which case
to open which specific ticket is available. This enables developers to learn about the issues affecting their project,
understand the impact on the running application and take action in time.

Every organization is different though. We believe that the best way modern DevSecOps teams can automate their specific
workflows is via code.

## FAQ
### What happens if the tool is run multiple times?
We will not open new Jira tickets for the same issue.
Each ticket opened by this tool contains a unique ID in the ticket summary.
If a ticket with this ID exists already, no additional ticket gets created.
Optionally, the tool can add comments to existing tickets - see the `--comment` option above.

### But what if someone removes the ID from the ticket summary?
Then this won't work anymore. However, there's anyhow a better solution: configure Jira to support a custom field
to contain external ticket IDs for your issues. Change this code to set these fields instead of writing to the summary.

### So why didn't you simply do this instead?
We wanted a solution that works out of the box for you. Jira doesn't have a default field we could use for this purpose.
