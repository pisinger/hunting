# Hunting Microsoft Defender admin activity with KQL

Queries for Defender Advanced Hunting that answer one question: who changed what in Microsoft Defender, and when. They cover detection rules, suppression rules, Defender for Endpoint settings, indicators, roles, device response actions, incident handling, Defender for Office 365 policies, Sentinel analytics rules and the Entra roles that grant access to all of it. The observations, timestamps and counts are from a test tenant; actor, agent, device, policy and rule names, account identifiers, and IP addresses have been generalized. Event coverage varies, so validate availability and fields in your own tenant before relying on a query.

## Where Defender admin activity is recorded

Defender does not have one admin audit table. The activity is spread over four places, and only one of them is a table you can hunt in the way the portal Audit page suggests.

| Source | What it records | Where it lives |
| --- | --- | --- |
| `CloudAppEvents`, `Workload = "Microsoft365Defender"` | Custom detection rules (`CreateCustomDetection`, `EditCustomDetection`, `DeleteCustomDetection`, `ChangeCustomDetectionRuleStatus`, `RunCustomDetection`), alert suppression rules, incident changes, case management changes | Defender XDR |
| `CloudAppEvents`, `Workload = "MicrosoftDefenderForEndpoint"` | Advanced features, data retention, onboarding and offboarding packages, indicators, MDE roles, device response actions and live response | Defender XDR |
| `CloudAppEvents`, `Application = "Microsoft Exchange Online"` | Defender for Office 365 and Exchange Online Protection policy changes, logged as Exchange admin cmdlets (`Set-AntiPhishPolicy`, `Set-SafeLinksPolicy`, and so on) | Defender XDR |
| `CloudAppEvents`, `Workload = "AzureActiveDirectory"` | Entra role assignments that give someone Defender access (`Add member to role.`, `Remove member from role.`) | Defender XDR |
| `CloudAppEvents`, `Workload = "URBAC"` | Defender XDR Unified RBAC: `CreateRole`, `CreateAssignment` and related role and assignment operations | Defender XDR |
| `CloudAppEvents`, `Workload = "MicrosoftDefenderForIdentity"` | Defender for Identity settings: sensor activation mode, remediation action accounts, and the other operations in the audit log reference | Defender XDR |
| `CloudAppEvents`, `Workload = "MicrosoftSecurityForAI"` | Security for AI settings: real-time protection policy rules and prompt evidence collection | Defender XDR |
| `CloudAuditEvents`, `DataSource = "Azure Logs"` | Sentinel automation rule control-plane operations | Defender XDR; inspect `AzureResourceId` for the rule resource path |
| `IntuneAuditLogs` | Endpoint security policy changes (ASR, antivirus, EDR) for Windows and Linux, made in the Defender portal or the Intune admin center | Sentinel workspace table |
| `SentinelAudit` | Sentinel analytics rule create, update, delete and failed saves, with the caller and the caller IP | Sentinel workspace table |

The same events appear in the Audit page of the Defender portal (Microsoft Purview unified audit log). Hunting them in `CloudAppEvents` gives you KQL, joins with sign-in data, and custom detections on top. The Audit page keeps them longer: Advanced Hunting only keeps 30 days.

## Things that surprised me

These observations shape the queries below; event availability and volume vary by environment.

- **`IsAdminOperation` is `0` for Defender events.** The flag is only set for Exchange and Entra style admin operations. A filter on `IsAdminOperation == true` finds Exchange cmdlets and Entra role changes and misses every Defender portal change. Filter on the workload in `RawEventData` instead.
- **The actor is not always in `AccountDisplayName`.** Incident changes made by an application (Sentinel, a SOAR app, an API client) have empty `AccountId` and `AccountDisplayName`. The app name sits in `RawEventData.AppAccessContext.ClientAppName`.
- **`UserType` does not tell you human from app for case management events.** Case events from applications and Defender itself arrive with `UserType = 0` (a regular user), with actor names such as `API-App:<app name>` and `Microsoft 365 Defender-IncidentCreation`. The shared preamble classifies by name first and by `UserType` second.
- **`UserType` is inconsistent for one account.** Defender for Identity events carry `UserType = 0` and indicator events carry `UserType = 7`, for the same admin who has `UserType = 2` elsewhere. Do not filter on `UserType = 2` to find admins.
- **Event fields are not documented in one place.** Custom detection events carry `RuleName`, `Query`, `AlertSeverity` and `RuleFrequency`. Response actions carry `DeviceName`, `DeviceGroup`, `ActionComment` and `ActionScope`. For operations I could not generate, the queries return the whole property bag as `Details` so you can see what the event holds before you build on it.
- **`bag_remove` does not exist in Advanced Hunting.** The function is `bag_remove_keys`.
- **`Set-AdminAuditLogConfig` can be generated by service activity.** Do not assume every event represents a person changing the audit setting. Query 17 excludes a known service actor; review and adapt that exclusion for your environment. Check `AdminAuditLogEnabled` in the parameters when a person runs it.

## Run the queries

- Advanced Hunting (Defender portal) or `POST /v1.0/security/runHuntingQuery` (`ThreatHunting.Read.All`).
- `CloudAppEvents` uses `Timestamp`. `SentinelAudit` is a workspace table with `TimeGenerated` and needs the Sentinel workspace connected to Defender.
- Advanced Hunting keeps 30 days. `CloudAppEvents` can be large, and the preamble parses `RawEventData` before it filters on the workload. Keep `lookback` short while you tune, and filter on `ActionType` first if you need it faster.
- Auditing must be on in Microsoft Purview. It is on by default.

### Shared preamble: `DefenderAdmin()`

Queries 1 to 8c, 10 to 12 and 14 to 18 start with this block. It reads the Defender workloads (`Microsoft365Defender`, `MicrosoftDefenderForEndpoint`, `MicrosoftDefenderExperts`, `URBAC` for Unified RBAC, `MicrosoftDefenderForIdentity` and `MicrosoftSecurityForAI`) from `CloudAppEvents`, works out who acted, and keeps everything else in `Details`. Paste it at the top of each query. Queries 5, 9 and 13 do not use it.

```kql
let DefenderAdmin = (lookback: timespan) {
    let identities = IdentityInfo
        | where Timestamp > ago(30d)
        | summarize arg_max(Timestamp, AccountUpn, AccountDisplayName) by AccountObjectId
        | project IdentityObjectId = AccountObjectId, IdentityUpn = AccountUpn, IdentityName = AccountDisplayName;
    CloudAppEvents
    | where Timestamp > ago(lookback)
    | extend R = parse_json(RawEventData)
    | extend Workload = tostring(R.Workload)
    | where Workload in ("Microsoft365Defender", "MicrosoftDefenderForEndpoint", "MicrosoftDefenderExperts", "URBAC",
        "MicrosoftDefenderForIdentity", "MicrosoftSecurityForAI")
    | extend RawUser = tostring(R.UserId)
    | extend ActorObjectId = coalesce(AccountObjectId, extract(@"/([0-9a-f]{8}-[0-9a-f-]{27})$", 1, RawUser),
        extract(@"^([0-9a-f]{8}-[0-9a-f-]{27})$", 1, tostring(R.UserKey)))
    | join kind=leftouter identities on $left.ActorObjectId == $right.IdentityObjectId
    | extend ActorName = coalesce(AccountDisplayName, IdentityName, tostring(R.AppAccessContext.ClientAppName), RawUser, "(unknown)")
    | extend ActorUpn = tolower(coalesce(iff(RawUser contains "@", RawUser, ""), IdentityUpn, iff(AccountId contains "@", AccountId, "")))
    | extend Actor = coalesce(ActorUpn, ActorName)
    | extend ActorKind = case(
        ActorName startswith "API-App:" or ActorName startswith "Microsoft 365 Defender-" or ActorName =~ "system", "application",
        toint(R.UserType) in (2, 7), "admin",
        toint(R.UserType) in (5, 6), "application",
        toint(R.UserType) == 4, "system",
        toint(R.UserType) == 0, "user",
        "other")
    | extend Details = bag_remove_keys(R, dynamic(["CreationTime", "Id", "OrganizationId", "UserKey", "UserType", "Workload",
        "RecordType", "ClientIP", "UserId", "Operation", "ActorContextId", "AppAccessContext"]))
    | project Timestamp, ReportId, Workload, Operation = ActionType, Actor, ActorUpn, ActorName, ActorKind,
        ActorObjectId, IPAddress, CountryCode, Details
};
```

`Actor` is the admin's UPN when the event names one or `IdentityInfo` can resolve the object ID to one, and the display name or app name otherwise. `ActorUpn` is only the UPN, `ActorName` is the display name or app name, and `ActorObjectId` is the Entra object ID. Applications have no UPN, so their `Actor` is the app name. `ActorKind` is `application` for an app, API client or Defender itself, `admin` for `UserType` 2 or 7, and `user` for `UserType = 0`. Treat it as a first filter, not a verdict. The same person shows up as `admin` on some operations and `user` on others: Defender for Identity events carry `UserType = 0` and the indicator events carry `UserType = 7`, for the same admin account. For that reason the behavior queries (14 and 15) filter on `ActorKind != "application"` and not on `admin`.

---

## A. What is there and who is doing it

### 1. Coverage: which Defender admin operations your tenant produces

Run this first. It shows which operations exist in your tenant, so you know which of the later queries can return anything.

```kql
DefenderAdmin(30d)
| summarize Events = count(), Actors = make_set(Actor, 5), First = min(Timestamp), Last = max(Timestamp) by Workload, Operation
| order by Workload asc, Events desc
```

Sample output:

```text
Workload               | Operation                  | Events | Actors                 | Last
-----------------------+----------------------------+--------+------------------------+---------------------
Microsoft365Defender   | UpdateIncidentStatus       | 150    | ["admin1@example.com"… | 2026-11-09T10:30:19Z
Microsoft365Defender   | AddedCommentToCase         | 187    | ["API-App:Example SOA… | 2026-11-05T13:15:13Z
Microsoft365Defender   | CreateCustomDetection      | 1      | ["admin1@example.com"] | 2026-10-27T15:46:28Z
MicrosoftDefenderForE… | SetAdvancedFeatures        | 2      | ["admin4@example.com"] | 2026-11-09T12:31:27Z
MicrosoftDefenderForE… | DeleteIndicator            | 1      | ["admin4@example.com"] | 2026-11-09T12:32:22Z
MicrosoftDefenderForI… | RemediationActionConfigur… | 4      | ["admin4@example.com"] | 2026-11-09T12:35:23Z
```

In the test tenant the settings operations were almost silent: one onboarding package download, one custom detection create, one investigation package. Operations that never appear here (`SetAdvancedFeatures`, `ChangeDataRetention`, indicator and role operations, suppression rules, `IsolateDevice`, live response) were not exercised, so queries 4, 6, 7, 8 and 10 returned few or no rows there. They are built from the Microsoft documentation of the audit log operation names, not from observed events.

### 2. Who performs Defender admin activity

Every actor, what kind of actor it is, how many operations it ran, from how many IPs and countries.

```kql
DefenderAdmin(30d)
| summarize Events = count(), Operations = dcount(Operation), TopOperations = make_set(Operation, 6), IPs = dcount(IPAddress),
    Countries = make_set(CountryCode, 4), First = min(Timestamp), Last = max(Timestamp) by Actor, ActorKind
| order by Events desc
```

Sample output:

```text
Actor                | ActorKind   | Events | Operations | TopOperations                        | IPs
---------------------+-------------+--------+------------+--------------------------------------+----
Sentinel             | application | 1923   | 9          | ["UpdateIncidentStatus","EditIncide… | 73
Example SOAR app     | application | 329    | 4          | ["UnAssignUserFromIncident","AddCom… | 3
Admin A              | admin       | 47     | 8          | ["UpdateIncidentStatus","UpdateInci… | 6
Admin B              | admin       | 41     | 10         | ["EditIncidentClassification","Chan… | 8
Example triage agent | user        | 9      | 1          | ["AddTagsToIncident"]                | 6
```

Look for: actors you do not recognise, applications that suddenly show up, and admins with many IPs. The Security Copilot agent appearing as an actor is the same agent user hunted in `agent-hunting.md`. Agents that close or tag incidents show up here as ordinary actors.

---

## B. Detection engineering: custom detections, suppression and analytics rules

These are the changes that weaken what the SOC sees. A deleted or disabled rule, or a new suppression rule, means an attack stops producing alerts.

### 3. Custom detection rule changes

Create, edit, delete, turn on or off, and manual runs, with the rule name, severity, frequency and the start of the KQL.

```kql
DefenderAdmin(30d)
| where Operation in ("CreateCustomDetection", "EditCustomDetection", "DeleteCustomDetection",
    "ChangeCustomDetectionRuleStatus", "RunCustomDetection")
| project Timestamp, Operation, Actor, IPAddress, RuleId = tostring(Details.RuleId), RuleName = tostring(Details.RuleName),
    Severity = tostring(Details.AlertSeverity), Frequency = tostring(Details.RuleFrequency),
    Query = substring(replace_string(tostring(Details.Query), "\r\n", " "), 0, 120)
| order by Timestamp desc
```

Sample output:

```text
Timestamp            | Operation             | Actor   | IP address | Rule ID | Rule name          | Severity | Frequency
---------------------+-----------------------+---------+------------+---------+--------------------+----------+----------
2026-11-02T21:04:31Z | RunCustomDetection    | Admin A | 192.0.2.21 | 50867   | Example detection… | —        | —
2026-10-27T15:46:28Z | CreateCustomDetection | Admin A | 192.0.2.4  | 50867   | Example detection… | Medium   | 1H
```

Both events include this query excerpt:

```kusto
CloudAppEvents | where ActionType == "ExampleAction" | ...
```

`Severity` and `Frequency` are only present on the create event in the test tenant. `Query` holds the full rule logic, so a delete or edit event lets you reconstruct what the rule covered. Alert on `DeleteCustomDetection` and `ChangeCustomDetectionRuleStatus` for rules you care about.

### 4. Alert suppression rule changes

Not exercised in the test tenant: no suppression rule events, so this query returned no rows. It follows the documented operations (`CreateSuppressionRule`, `EditSuppressionRule`, `EnableSuppressionRule`, `DisableSuppressionRule`, `DeleteSuppressionRule`). A new suppression rule is a quiet way to blind a detection, so keep it as a standing query.

```kql
DefenderAdmin(30d)
| where Operation endswith "SuppressionRule"
| project Timestamp, Operation, Actor, ActorKind, IPAddress, Details = tostring(Details)
| order by Timestamp desc
```

Read `Details` before you build on it: the fields that name the rule and its conditions are not documented, and I could not observe them.

### 5. Sentinel analytics rule changes

For tenants with Sentinel in the Defender portal, analytics rules are detections too. `SentinelAudit` records every create, update, delete and failed save, with the caller and the caller IP.

```kql
SentinelAudit
| where TimeGenerated > ago(30d)
| where SentinelResourceType == "Analytic Rule"
| extend X = todynamic(ExtendedProperties)
| extend Change = case(
    Description has "deleted", "deleted",
    Description has "Create or update" and Status == "Success", "created or updated",
    Status == "Failure", "failed",
    "other")
| summarize Events = count(), Rules = dcount(SentinelResourceName), RuleNames = make_set(SentinelResourceName, 4),
    IPs = make_set(tostring(X.CallerIpAddress), 3), Last = max(TimeGenerated)
    by Caller = tostring(X.CallerName), Change
| order by Events desc
```

Sample output:

```text
Caller             | Change             | Events | Rules | RuleNames                            | IPs
-------------------+--------------------+--------+-------+--------------------------------------+-------------------
app-id             | created or updated | 674    | 154   | ["Example_Detection_A","Example_Det… | ["192.0.2.33","19…
app-id             | failed             | 607    | 159   | ["Example_Detection_C",...]          | [...]
app-id             | deleted            | 200    | 120   | ["Example_Detection_D",...]          | [...]
admin3@example.com | created or updated | 2      | 2     | ["Example_Detection_E",...]          | ["192.0.2.91"]
```

`CallerName` is an application ID when a pipeline or an automation deploys the rules and a UPN when a person does. A pipeline may create, update or delete many rules during deployment. Confirm that the caller matches the expected automation before treating that pattern as normal. `ExtendedProperties` also carries `OriginalResourceState` for updates if you need the before value.

### 5b. Sentinel automation rule changes

Automation rule changes are Azure control-plane operations. In Advanced Hunting, find them in `CloudAuditEvents` with `DataSource = "Azure Logs"`. Parse the rule ID from `AzureResourceId`; inspect `RawEventData` and `AdditionalFields` for actor and status fields because their shape can vary by event.

```kql
CloudAuditEvents
| where Timestamp > ago(30d)
| where DataSource =~ "Azure Logs"
| where OperationName contains "Microsoft.SecurityInsights/automationRules"
| extend RuleId = extract(@"(?i)/automationRules/([^/?]+)", 1, AzureResourceId),
         Status = tostring(RawEventData["status"]),
         SubStatus = tostring(RawEventData["subStatus"])
| project Timestamp, ActionType, OperationName, RuleId, AzureResourceId,
          IPAddress, Status, SubStatus, RawEventData, AdditionalFields
| order by Timestamp desc
```

This query was not exercised in the original test tenant. Confirm which operations and payload fields your workspace returns before building an alert around them.

---

## C. Defender for Endpoint settings, indicators and roles

### 6. Advanced features, data retention and onboarding packages

Operations: `SetAdvancedFeatures`, `ChangeDataRetention`, `DownloadOnboardingPkg`, `DownloadOffboardingPkg`. Microsoft logs only advanced features that are generally available. Downloading an offboarding package is how someone removes devices from Defender.

```kql
DefenderAdmin(30d)
| where Operation in ("ChangeDataRetention", "SetAdvancedFeatures", "DownloadOnboardingPkg", "DownloadOffboardingPkg")
| project Timestamp, Operation, Actor, ActorKind, IPAddress, CountryCode, Details = tostring(Details)
| order by Timestamp desc
```

Sample output:

```text
Timestamp            | Operation             | Actor   | ActorKind | IPAddress  | Details
---------------------+-----------------------+---------+-----------+------------+-------------------------------------
2026-11-09T12:31:27Z | SetAdvancedFeatures   | Admin D | admin     | 192.0.2.53 | {"SettingName":"Restrict correlatio…
2026-11-09T12:31:19Z | SetAdvancedFeatures   | Admin D | admin     | 192.0.2.28 | {"SettingName":"Low fidelity enrich…
2026-11-03T08:10:44Z | DownloadOnboardingPkg | Admin D | admin     | 192.0.2.12 | {"DeploymentMethod":"ExampleDeploym…
```

`SetAdvancedFeatures` carries `SettingName` and `SettingsNewValue` and no old value, so you see what a setting was set to but not what it was before. Each toggle is its own event. The events reached `CloudAppEvents` within minutes of the change.

### 6b. Endpoint security policies (ASR, antivirus, EDR) for Windows and Linux

Policies you edit under Endpoints > Configuration management > Endpoint security policies in the Defender portal are Intune policies. I checked `CloudAppEvents`, `DeviceEvents`, `AlertEvidence`, `AlertInfo`, `OfficeActivity` and `AuditLogs` by policy name and policy ID, more than 20 minutes after the edits, while other `CloudAppEvents` rows from the same period had arrived: none of them hold these events. Only `IntuneAuditLogs` does, a Sentinel workspace table that Advanced Hunting can query in this tenant. That table is available when the Intune diagnostic setting sends the audit log to the workspace. Otherwise, check the Intune audit log in the admin center. The actor UPN is in `Properties.Actor.UPN`, and `Properties.Actor.ApplicationName` tells you where the change was made: `WindowsDefenderATP` means the Defender portal, `Microsoft Intune portal extension` means the Intune admin center, anything else is an integration or an automation account. Created or changed policies carry only the new values, so you see which policy changed, not what changed in it. The query skips the `Get` operations, which are read noise (one integration produced thousands in the test tenant).

```kql
IntuneAuditLogs
| where TimeGenerated > ago(30d)
| where OperationName matches regex @"^(Create|Patch|Delete|Assign|Update) "
| where OperationName has_any ("DeviceManagementConfigurationPolicy", "DeviceManagementIntent", "DeviceConfiguration", "DeviceCompliancePolicy")
| extend P = parse_json(Properties)
| extend Actor = coalesce(tolower(tostring(P.Actor.UPN)), tostring(P.Actor.ApplicationName)),
    ViaApp = tostring(P.Actor.ApplicationName),
    Policy = tostring(P.TargetDisplayNames[0]),
    Platform = tostring(P.Targets[0].ModifiedProperties[2].New)
| summarize Changes = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Actor, ViaApp, OperationName, Policy, Platform
| order by Last desc
```

Sample output (the first three rows are ASR and antivirus policy edits made in the Defender portal, one of them for Linux):

```text
Actor              | ViaApp                 | OperationName              | Policy               | Platform  | Changes | Last
-------------------+------------------------+----------------------------+----------------------+-----------+---------+---------------------
admin1@example.com | WindowsDefenderATP     | Patch DeviceManagementCon… | Linux policy example | Linux     | 1       | 2026-11-09T18:48:50Z
admin1@example.com | WindowsDefenderATP     | Patch DeviceManagementCon… | ASR policy example   | Windows10 | 1       | 2026-11-09T18:47:54Z
admin1@example.com | WindowsDefenderATP     | Patch DeviceManagementCon… | Audit policy example | Windows10 | 1       | 2026-11-09T18:47:28Z
admin2@example.com | Microsoft Intune port… | Delete DeviceManagementCo… | (null)               | (null)    | 2       | 2026-10-23T09:40:22Z
```

A `Delete` row has no policy name, so keep the `PolicyId` from `Properties.TargetObjectIds` if you need to tie it back to an earlier create. Policy changes are the closest thing to settings drift in this file: an ASR rule switched from block to audit sits here, not in the Defender admin events.

### 7. Indicator changes

Operations: `AddIndicator`, `EditIndicator`, `DeleteIndicator`. An indicator with an allow action is how a file, IP address or domain is exempted from detection. A delete event carries the whole indicator, so you can see what was removed.

```kql
DefenderAdmin(30d)
| where Operation in ("AddIndicator", "EditIndicator", "DeleteIndicator")
| project Timestamp, Operation, Actor, ActorKind, IPAddress, Type = tostring(Details.IndicatorType), Value = tostring(Details.IndicatorValue),
    Action = tostring(Details.IndicatorAction), Title = tostring(Details.IndicatorTitle), Source = tostring(Details.CreatedBySource)
| order by Timestamp desc
```

Sample output:

```text
Timestamp            | Operation       | Actor   | ActorKind | Type      | Value     | Action | Title | Source
---------------------+-----------------+---------+-----------+-----------+-----------+--------+-------+-------
2026-11-09T12:32:22Z | DeleteIndicator | Admin D | admin     | IpAddress | 192.0.2.9 | Block  | test  | Portal
```

Only the delete was exercised. Other fields on the event: `IndicatorAlertSeverity`, `IndicatorGenerateAlerts`, `IndicatorId`, `IndicatorBypassDuration`, `IndicatorDescription`. Alert on `IndicatorAction == "Allow"` for adds and edits, and on deletes of block indicators.

### 8. Defender roles and Defender Experts permissions

Operations: `AddRole`, `EditRole`, `DeleteRole` (MDE roles), `DefenderExpertsAnalystPermissionCreated`, `DefenderExpertsAnalystPermissionModified`, and everything in the `URBAC` workload (`CreateRole`, `CreateAssignment` and related). The URBAC operations were exercised in the test tenant, the MDE role and Defender Experts ones were not.

```kql
DefenderAdmin(30d)
| where Operation in ("AddRole", "EditRole", "DeleteRole", "DefenderExpertsAnalystPermissionCreated", "DefenderExpertsAnalystPermissionModified")
    or Workload == "URBAC"
| project Timestamp, Workload, Operation, Actor, ActorKind, IPAddress, Details = substring(tostring(Details), 0, 300)
| order by Timestamp desc
```

Sample output:

```text
Timestamp            | Workload | Operation        | Actor   | IPAddress | Details
---------------------+----------+------------------+---------+-----------+-------------------------------------
2026-11-04T09:36:37Z | URBAC    | CreateAssignment | Admin A | 192.0.2.1 | {"AddedRoleAssignment":["<role-id>"…
2026-11-04T09:36:36Z | URBAC    | CreateRole       | Admin A | 192.0.2.6 | {"AddedRolePermission":["microsoft.…
```

A role event names the permission strings (`AddedRolePermission`). An assignment event names the scopes (workloads such as `Mde`, `Mdo`, `Mdi`, `Mda`), but only IDs for the role and the assigned principals, so join those IDs to a role list when you review it.

### 8b. Defender for Identity settings

Sensor activation mode, remediation action accounts, global exclusions, notification recipients, thresholds, syslog and VPN settings. The workload is `MicrosoftDefenderForIdentity`. The event has a `ResultStatus` and, for some operations, a `ResultDescription` that says what the setting became. Global exclusions and a deleted sensor are the two to alert on: they remove coverage.

```kql
DefenderAdmin(30d)
| where Workload == "MicrosoftDefenderForIdentity"
| project Timestamp, Operation, Actor, IPAddress, Result = tostring(Details.ResultStatus), Description = tostring(Details.ResultDescription)
| order by Timestamp desc
```

Sample output:

```text
Timestamp            | Operation                  | Actor   | IPAddress   | Result    | Description
---------------------+----------------------------+---------+-------------+-----------+---------------------------------
2026-11-09T12:35:57Z | SensorActivationMethodCon… | Admin D | 192.0.2.88  | Succeeded | Updated sensors activation mode…
2026-11-09T12:35:23Z | RemediationActionConfigur… | Admin D | 192.0.2.110 | Succeeded | Updated action accounts mode to…
2026-11-09T12:35:20Z | RemediationActionConfigur… | Admin D | 192.0.2.110 | Succeeded | Updated action accounts mode to…
```

Two things to know. Each change produces two events: one with the description and one without, so count changes by the pairs. The usefulness of IP-based baselines depends on how portal traffic is routed in your environment. The operations for exclusions, sensors, recipients and thresholds were not exercised, and they are documented in the audit log reference.

### 8c. Security for AI settings

Real-time protection policy rules for AI agents and prompt evidence collection. Disabling a rule or evidence collection weakens detection for agents, so these belong next to the other detection-loss queries.

```kql
DefenderAdmin(30d)
| where Workload == "MicrosoftSecurityForAI"
| project Timestamp, Operation, Actor, IPAddress, Setting = coalesce(tostring(Details.AttributeName), tostring(Details.RuleID)),
    NewStatus = coalesce(tostring(Details.AttributeNewStatus), tostring(Details.RuleStatus)),
    ThreatScenarios = tostring(Details.ThreatScenarioScopeTo)
| order by Timestamp desc
```

Sample output:

```text
Timestamp            | Operation                  | Actor   | Setting                | NewStatus | ThreatScenarios
---------------------+----------------------------+---------+------------------------+-----------+-------------------------------------
2026-11-09T12:38:49Z | DisabledSecurityForAIProm… | Admin D | PromptEvidenceCollect… | Disabled  | —
2026-11-09T12:38:45Z | EnabledSecurityForAIPromp… | Admin D | PromptEvidenceCollect… | Enabled   | —
2026-11-09T12:38:27Z | EnabledSecurityForAIRTPPo… | Admin D | <policy-rule-id>       | Enabled   | ["ExampleScenarioA","ExampleScenari…
2026-10-27T12:53:37Z | CreatedSecurityForAIRTPPo… | Admin A | <policy-rule-id>       | Enabled   | [...]
2026-10-27T12:52:56Z | DisabledSecurityForAIRTPP… | Admin A | <policy-rule-id>       | Disabled  | [...]
```

The rule event also carries scope fields (`AgentIDScopeTo`, `AzureSubscriptionScopeTo`, `PowerPlatformEnvironmentScopeTo`, `RiskLevelScopeTo`) for narrowing a rule to certain agents, so an edit that shrinks the scope is a change worth reading in `Details`.

### 9. Entra roles that grant Defender access

Who got, or lost, a security role. This is the control that decides who can run every other query in this file. The role list is the part to tune.

```kql
let securityRoles = dynamic(["Global Administrator", "Security Administrator", "Security Operator", "Security Reader",
    "Compliance Administrator", "Exchange Administrator", "Attack Simulation Administrator", "Attack Payload Author"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("member to role", "member from role", "eligible member")
| extend R = parse_json(RawEventData)
| mv-apply m = R.ModifiedProperties on (summarize Props = make_bag(bag_pack(tostring(m.Name), tostring(m.NewValue))))
| extend Role = tostring(Props["Role.DisplayName"])
| where Role in (securityRoles)
| project Timestamp, ActionType, Role, Target = tostring(R.ObjectId),
    Actor = coalesce(AccountDisplayName, tostring(R.Actor[0].ID)), ActorKind = iff(toint(R.UserType) == 4, "system/PIM", "user"),
    Result = tostring(R.ResultStatus)
| order by Timestamp desc
```

Sample output:

| Timestamp | Action | Role | Target | Actor | Actor kind | Result |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-09T07:41:19Z | Add member to role. | Global Administrator | admin3@example.com | MS-PIM | system/PIM | Success |
| 2026-11-04T09:24:39Z | Add member to role. | Global Administrator | admin3@example.com | MS-PIM | system/PIM | Success |
| 2026-10-28T12:58:11Z | Add member to role. | Global Administrator | admin3@example.com | Admin C | user | Success |

`MS-PIM` as the actor is most likely a PIM activation of an eligible role, the target being the person who activated it. The same row with a human actor is a direct assignment. The two kinds look the same in the role name and differ in the actor, which is the field to read.

---

## D. Device response actions

### 10. Response actions and live response by actor

Isolation, release from isolation, live response, investigation packages, antivirus scans, app restrictions, file quarantine, file downloads and device offboarding. `ActionComment` is the free-text reason the analyst typed.

```kql
DefenderAdmin(30d)
| where Operation in ("IsolateDevice", "ReleaseFromIsolation", "RunLiveResponseSession", "RunLiveResponseApi", "LiveResponseGetFile",
    "CollectInvestigationPackage", "RunAntiVirusScan", "RestrictAppExecution", "RemoveAppRestrictions", "StopAndQuarantineFile",
    "DownloadFile", "LogsCollection", "DeviceOffBoarding")
| summarize Actions = count(), Devices = dcount(tostring(Details.DeviceName)), DeviceNames = make_set(tostring(Details.DeviceName), 5),
    Comments = make_set(tostring(Details.ActionComment), 3), First = min(Timestamp), Last = max(Timestamp) by Actor, Operation
| order by Actions desc
```

These are response actions, not configuration changes. They tell you who acted on a device and when, not that a setting drifted, so treat them as misuse hunting. Isolation and live response were confirmed in the test tenant (`IsolateDevice` carries `ActionComment` and `ActionScope`, `RunLiveResponseSession` carries the typed command in `CommandsString`). A triggered antivirus scan shows up as `RunAntiVirusScan` and a release from isolation as `ReleaseFromIsolation`, both after an audit lag of about 10 to 20 minutes.

Sample output (investigation package, isolation and live response occurred in the test tenant):

```text
Actor              | Operation                  | Actions | Devices | DeviceNames                    | Comments                    | First                | Last
-------------------+----------------------------+---------+---------+--------------------------------+-----------------------------+----------------------+---------------------
Admin E            | CollectInvestigationPacka… | 1       | 1       | ["endpoint-01"]                | ["example action"]          | 2026-10-27T15:14:48Z | 2026-10-27T15:14:48Z
admin2@example.com | IsolateDevice              | 1       | 1       | ["endpoint-02"]                | ["example response action"] | 2026-11-09T18:30:24Z | 2026-11-09T18:30:24Z
admin2@example.com | RunLiveResponseSession     | 4       | 2       | ["endpoint-02", "endpoint-03"] | [""]                        | 2026-11-09T18:28:39Z | 2026-11-09T18:29:57Z
```

Live response is the highest-impact action in this list: it is a remote shell on the device. A live response session with no comment, or one from an admin who never ran it before, deserves a look. The same event also carries `DeviceGroup` and `ActionScope` (for example `Quick`).

---

## E. Incident handling

Incident and case changes are in the audit log as well. They are not settings, but they decide what happens to every alert. Closing incidents in bulk or changing severity is how an attack is hidden in plain sight.

### 11. Who changes incidents, by kind of actor

```kql
DefenderAdmin(30d)
| where Operation in ("UpdateIncidentStatus", "EditIncidentClassification", "UpdateIncidentSeverity", "UpdateIncidentResolvingComment",
    "AssignUserToIncident", "UnAssignUserFromIncident", "AddTagsToIncident", "RemoveTagsFromIncident", "AddCommentToIncident")
| summarize Changes = count(), Incidents = dcount(tostring(Details.IncidentId)), Last = max(Timestamp) by ActorKind, Actor, Operation
| order by Changes desc
```

Sample output:

```text
ActorKind   | Actor            | Operation                | Changes | Incidents | Last
------------+------------------+--------------------------+---------+-----------+---------------------
application | Sentinel         | RemoveTagsFromIncident   | 512     | 406       | 2026-11-06T09:50:25Z
application | Sentinel         | AddCommentToIncident     | 411     | 405       | 2026-11-05T13:15:14Z
application | Example SOAR app | UnAssignUserFromIncident | 128     | 36        | 2026-10-21T15:13:53Z
application | Sentinel         | UpdateIncidentStatus     | 115     | 46        | 2026-11-08T13:11:13Z
```

Applications make most incident changes. That is the Sentinel integration synchronising incident state, not people. Add `| where ActorKind == "admin"` to see only humans. The `Incidents` column counts distinct incident IDs: a changes-to-incidents ratio above 1 means the same incident was changed repeatedly.

### 12. Bulk closure by one actor

Many incidents resolved by the same person in one hour. Tune `window` and `threshold`. Applications are excluded because integrations close incidents in bulk by design.

```kql
let window = 1h;
let threshold = 10;
DefenderAdmin(30d)
| where Operation == "UpdateIncidentStatus" and tostring(Details.Status) == "Closed"
| where ActorKind != "application"
| summarize Closed = dcount(tostring(Details.IncidentId)), First = min(Timestamp), Last = max(Timestamp), IPs = make_set(IPAddress, 3)
    by Actor, Window = bin(Timestamp, window)
| where Closed >= threshold
| order by Closed desc
```

No rows in the test tenant at a threshold of 10. At a threshold of 3 it returned two admins who closed 5 and 3 incidents within a few minutes. The status values in the test tenant were `Open`, `InProgress` and `Closed`. A hit here is not proof of abuse: a clean-up after a noisy rule looks the same. Check the classification in `EditIncidentClassification` next to it.

---

## F. Defender for Office 365 policy changes

Defender for Office 365 and EOP policies are Exchange objects, so their changes are Exchange admin cmdlets in `CloudAppEvents`. Exchange admin audit logs every cmdlet that changes something by default.

### 13. Email protection policy changes with the changed parameters

Anti-phishing, anti-malware, Safe Links, Safe Attachments, anti-spam, Tenant Allow/Block List, quarantine policies, preset security policies, connectors, mail flow rules and the audit configuration itself. The object list in `mdoObjects` is the part to tune. The query resolves the actor itself because these events do not name the person (see below).

```kql
let mdoObjects = @"(AntiPhish|MalwareFilter|SafeLinks|SafeAttachment|HostedContentFilter|HostedOutboundSpamFilter|HostedConnectionFilter|TenantAllowBlockList|QuarantinePolicy|PhishSimOverride|SecOpsOverride|AtpPolicyForO365|ATPProtectionPolicyRule|EOPProtectionPolicyRule|ATPBuiltInProtectionRule|ReportSubmission|TeamsProtectionPolicy|AdvancedDelivery|DkimSigningConfig|AdminAuditLogConfig|TransportRule|InboundConnector|OutboundConnector)";
let names = IdentityInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, AccountDisplayName, AccountUpn) by AccountObjectId;
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType matches regex strcat(@"^(Set|New|Remove|Enable|Disable)-", mdoObjects)
| extend R = parse_json(RawEventData)
| extend UserId = tostring(R.UserId)
| extend ActorObjectId = coalesce(AccountObjectId, extract(@"/([0-9a-f]{8}-[0-9a-f-]{27})$", 1, UserId))
| join kind=leftouter names on $left.ActorObjectId == $right.AccountObjectId
| mv-apply p = R.Parameters on (summarize Params = make_bag(bag_pack(tostring(p.Name), tostring(p.Value))))
| extend Actor = coalesce(tolower(AccountUpn), tolower(iff(UserId contains "@", UserId, "")), AccountDisplayName, AccountDisplayName1, iff(UserId startswith "NT SERVICE", UserId, ""), ActorObjectId, UserId)
| project Timestamp, Cmdlet = ActionType, Object = coalesce(tostring(R.ObjectId), tostring(Params.Identity)), Actor,
    Result = tostring(R.ResultStatus), Parameters = tostring(Params)
| order by Timestamp desc
```

Sample output:

```text
Timestamp            | Cmdlet                     | Object                 | Actor   | Result | Parameters
---------------------+----------------------------+------------------------+---------+--------+-------------------------------------
2026-11-09T12:44:49Z | New-TenantAllowBlockListI… | —                      | Admin D | True   | {"Entries":"example.org","ListType"…
2026-11-09T12:43:08Z | New-TenantAllowBlockListI… | —                      | Admin D | True   | {"Entries":"example.com","ListType"…
2026-11-09T12:42:19Z | Set-MalwareFilterRule      | Example_AntiMalwarePo… | Admin D | True   | {"Identity":"Example_AntiMalwarePol…
2026-11-09T12:42:06Z | Set-MalwareFilterPolicy    | Example_AntiMalwarePo… | Admin D | True   | {"ZapEnabled":"False","FileTypeActi…
2026-11-09T12:41:24Z | Disable-MalwareFilterRule  | Custom_Anti-Malware    | Admin D | True   | {"Identity":"<rule-id>"}
```

Three things the test showed:

- **The person is not in `AccountDisplayName`.** For changes made in the Defender portal, `AccountDisplayName` is empty and `RawEventData.UserId` is a path that ends with the admin's object ID (`.../<tenant>.onmicrosoft.com/<object id>`). The query takes that object ID and looks the name up in `IdentityInfo`. If `IdentityInfo` has no row, `Actor` falls back to the object ID.
- **`IPAddress` is the Exchange service, not the admin.** It is an IPv6 address of the Exchange front end, so do not baseline admin IPs on these events.
- **The policy settings come back as the full set.** A `Set-MalwareFilterPolicy` event lists every setting of the policy, not only the one that changed (`ZapEnabled`, `FileTypes`, `FileTypeAction`, and so on), and there is no old value. To find what changed, compare two consecutive events for the same policy. `Disable-MalwareFilterRule` and the rule `Priority` change are separate events and show up as such.

Add `| where Actor !startswith "NT SERVICE"` to drop service account noise.

### 13b. Tenant Allow/Block List entries

An allow entry in the Tenant Allow/Block List overrides filtering for a sender, domain, URL or file, so it is the email equivalent of a detection exemption. One row per entry, with the verdict, list type and expiry.

```kql
let names = IdentityInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, AccountUpn) by AccountObjectId;
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-TenantAllowBlockListItems", "Set-TenantAllowBlockListItems", "Remove-TenantAllowBlockListItems")
| extend R = parse_json(RawEventData)
| mv-apply p = R.Parameters on (summarize Params = make_bag(bag_pack(tostring(p.Name), tostring(p.Value))))
| extend ActorObjectId = coalesce(AccountObjectId, extract(@"/([0-9a-f]{8}-[0-9a-f-]{27})$", 1, tostring(R.UserId)))
| join kind=leftouter names on $left.ActorObjectId == $right.AccountObjectId
| extend Verdict = case(tostring(Params.Allow) =~ "True", "Allow", tostring(Params.Block) =~ "True", "Block", "")
| project Timestamp, Cmdlet = ActionType, Verdict, ListType = tostring(Params.ListType), Entries = tostring(Params.Entries),
    RemoveAfterDays = tostring(Params.RemoveAfter), Notes = tostring(Params.Notes), Actor = coalesce(tolower(AccountUpn), AccountDisplayName, ActorObjectId)
| order by Timestamp desc
```

Sample output:

```text
Timestamp            | Cmdlet                     | Verdict | ListType | Entries                | RemoveAfterDays | ActorObjectId
---------------------+----------------------------+---------+----------+------------------------+-----------------+--------------
2026-11-09T12:44:49Z | New-TenantAllowBlockListI… | Allow   | Url      | example.org            | 45              | app-id
2026-11-09T12:43:25Z | New-TenantAllowBlockListI… | Allow   | Sender   | example.org;*.example… | 45              | app-id
2026-11-09T12:43:08Z | New-TenantAllowBlockListI… | Allow   | Sender   | example.com            | 45              | app-id
```

`RemoveAfter` is the number of days of inactivity after which an allow entry is removed. An entry allowing your own domain, or a wildcard on a large domain, is the one to question: attackers abuse allow entries for the same reason admins create them. `Notes` is empty in the sample, which is itself a finding in a tenant that wants a reason on every exemption.

---

## G. Behavior: who, from where, when

These queries do not look for a specific operation. They look for the actor behaving differently.

### 14. New IP address or new admin

Compares the last 3 days against the 27 days before. `NewActor` is true when the admin has no history at all.

```kql
let window = 3d;
let baseline = 27d;
let admins = DefenderAdmin(window + baseline) | where ActorKind != "application";
let knownIps = admins | where Timestamp < ago(window) | distinct Actor, IPAddress;
let knownActors = admins | where Timestamp < ago(window) | distinct Actor;
admins
| where Timestamp >= ago(window)
| join kind=leftanti knownIps on Actor, IPAddress
| join kind=leftouter (knownActors | extend KnownActor = true) on Actor
| summarize Events = count(), Operations = make_set(Operation, 5), First = min(Timestamp), Countries = make_set(CountryCode, 3)
    by Actor, IPAddress, NewActor = isnull(KnownActor)
| order by First asc
```

Sample output:

```text
Actor   | IPAddress  | NewActor | Events | Operations                           | First
--------+------------+----------+--------+--------------------------------------+---------------------
Admin B | 192.0.2.64 | false    | 1      | ["ChangedCaseSeverity"]              | 2026-11-06T15:41:53Z
Admin B | 192.0.2.12 | false    | 4      | ["UpdateIncidentStatus","AssignUser… | 2026-11-06T15:41:53Z
```

In environments where admins use shared or frequently changing egress addresses, a new IP alone can be noisy. A new IP combined with a configuration operation from queries 3, 4, 6, 7 or 8 is the signal. Raise the bar by joining `CountryCode` instead of the IP address.

### 15. Configuration changes outside working hours

Configuration and high-impact operations by an admin before `workStart`, after `workEnd`, or at the weekend. Times are UTC: shift them for your time zone.

```kql
let workStart = 6;
let workEnd = 19;
let configOps = dynamic(["CreateCustomDetection", "EditCustomDetection", "DeleteCustomDetection", "ChangeCustomDetectionRuleStatus",
    "CreateSuppressionRule", "EditSuppressionRule", "DeleteSuppressionRule", "DisableSuppressionRule", "EnableSuppressionRule",
    "ChangeDataRetention", "SetAdvancedFeatures", "DownloadOffboardingPkg", "AddIndicator", "EditIndicator", "DeleteIndicator",
    "AddRole", "EditRole", "DeleteRole", "IsolateDevice", "ReleaseFromIsolation", "RunLiveResponseSession", "DeviceOffBoarding"]);
DefenderAdmin(30d)
| where ActorKind != "application" and Operation in (configOps)
| extend Hour = hourofday(Timestamp), Weekend = dayofweek(Timestamp) in (0d, 6d)
| where Hour !between (workStart .. workEnd) or Weekend
| project Timestamp, Actor, Operation, IPAddress, CountryCode, Weekend
| order by Timestamp desc
```

No rows in the test tenant: the only configuration operations were during working hours.

### 16. Burst of configuration changes

Many configuration changes by one actor in one hour. A clean-up or a migration looks the same, so this is a prompt to check the actor, not a verdict.

```kql
let window = 1h;
let threshold = 5;
let configOps = dynamic(["CreateCustomDetection", "EditCustomDetection", "DeleteCustomDetection", "ChangeCustomDetectionRuleStatus",
    "CreateSuppressionRule", "EditSuppressionRule", "DeleteSuppressionRule", "DisableSuppressionRule", "EnableSuppressionRule",
    "ChangeDataRetention", "SetAdvancedFeatures", "AddIndicator", "EditIndicator", "DeleteIndicator", "AddRole", "EditRole", "DeleteRole"]);
DefenderAdmin(30d)
| where Operation in (configOps)
| summarize Changes = count(), Operations = make_set(Operation, 6), First = min(Timestamp), Last = max(Timestamp)
    by Actor, Window = bin(Timestamp, window)
| where Changes >= threshold
| order by Changes desc
```

No rows in the test tenant.

---

## H. Putting it together

### 17. One list of changes that weaken detection

The Defender, Exchange and Sentinel changes that reduce what you see, in one table with a plain-language reason. This is the query to turn into a custom detection or a weekly review. It joins three sources, so it needs the Sentinel workspace connected. Exchange rows count Tenant Allow/Block List allow entries, disabled or removed email protection rules and policies, and audit configuration changes.

```kql
let defenderRisky = DefenderAdmin(30d)
    | extend Why = case(
        Operation == "DeleteCustomDetection", "detection rule deleted",
        Operation == "ChangeCustomDetectionRuleStatus", "detection rule switched on or off",
        Operation in ("CreateSuppressionRule", "DisableSuppressionRule", "DeleteSuppressionRule", "EditSuppressionRule"), "alert suppression changed",
        Operation in ("ChangeDataRetention", "SetAdvancedFeatures"), "Defender for Endpoint setting changed",
        Operation in ("DownloadOffboardingPkg", "DeviceOffBoarding"), "devices offboarded",
        Operation in ("AddIndicator", "EditIndicator", "DeleteIndicator"), "indicator changed",
        Operation in ("AddRole", "EditRole", "DeleteRole"), "Defender role changed",
        Operation in ("RunLiveResponseSession", "RunLiveResponseApi", "IsolateDevice", "ReleaseFromIsolation"), "high-impact device action",
        "")
    | where isnotempty(Why)
    | project Timestamp, Source = "Defender portal", Actor, Operation, Why, IPAddress;
let names = IdentityInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, AccountDisplayName, AccountUpn) by AccountObjectId;
let auditTamper = CloudAppEvents
    | where Timestamp > ago(30d)
    | where ActionType == "Set-AdminAuditLogConfig"
        or ActionType matches regex @"^(Remove|Disable)-(AntiPhish|MalwareFilter|SafeLinks|SafeAttachment|HostedContentFilter|QuarantinePolicy)"
        or ActionType == "New-TenantAllowBlockListItems"
    | extend R = parse_json(RawEventData)
    | where tostring(R.UserId) !startswith "NT SERVICE"
    | mv-apply p = R.Parameters on (summarize Params = make_bag(bag_pack(tostring(p.Name), tostring(p.Value))))
    | where ActionType != "New-TenantAllowBlockListItems" or tostring(Params.Allow) =~ "True"
    | extend ActorObjectId = coalesce(AccountObjectId, extract(@"/([0-9a-f]{8}-[0-9a-f-]{27})$", 1, tostring(R.UserId)))
    | join kind=leftouter names on $left.ActorObjectId == $right.AccountObjectId
    | project Timestamp, Source = "Exchange", Actor = coalesce(tolower(AccountUpn), AccountDisplayName, AccountDisplayName1, tostring(R.UserId)),
        Operation = ActionType, Why = "audit or email protection setting changed", IPAddress = "";
let sentinelDeletes = SentinelAudit
    | where TimeGenerated > ago(30d)
    | where SentinelResourceType == "Analytic Rule" and Description has "deleted"
    | extend X = todynamic(ExtendedProperties)
    | project Timestamp = TimeGenerated, Source = "Sentinel", Actor = tostring(X.CallerName), Operation = "Analytics rule deleted",
        Why = SentinelResourceName, IPAddress = tostring(X.CallerIpAddress);
union defenderRisky, auditTamper, sentinelDeletes
| summarize Events = count(), Why = make_set(Why, 4), Last = max(Timestamp) by Source, Actor, Operation
| order by Events desc
```

Sample output:

```text
Source          | Actor   | Operation                  | Events | Why                              | Last
----------------+---------+----------------------------+--------+----------------------------------+---------------------
Sentinel        | app-id  | Analytics rule deleted     | 200    | ["Example_Detection_D",...]      | 2026-10-15T08:16:11Z
Exchange        | Admin D | New-TenantAllowBlockListI… | 5      | ["audit or email protection set… | 2026-11-09T12:44:49Z
Defender portal | Admin D | SetAdvancedFeatures        | 3      | ["Defender for Endpoint setting… | 2026-11-09T12:31:27Z
Defender portal | Admin D | DeleteIndicator            | 1      | ["indicator changed"]            | 2026-11-09T12:32:22Z
Exchange        | Admin D | Disable-MalwareFilterRule  | 1      | ["audit or email protection set… | 2026-11-09T12:41:24Z
Exchange        | Admin A | Set-AdminAuditLogConfig    | 1      | ["audit or email protection set… | 2026-10-16T09:35:11Z
```

The 200 deletes came from one application ID, most likely a pipeline redeploy. The `Set-AdminAuditLogConfig` event is one person running the cmdlet: check its `AdminAuditLogEnabled` value in query 13 to see whether auditing was turned on or off. The Defender for Identity and Security for AI changes from queries 8b and 8c are not in this list yet. Add the two workloads to `defenderRisky` if you want them in the weekly review.

### 18. Everything one admin did

The timeline to run when an admin account is in doubt. Replace the placeholder with a UPN or display name from query 2.

```kql
let actor = "<UPN or display name of the admin>";
DefenderAdmin(30d)
| where Actor =~ actor or ActorName =~ actor
| project Timestamp, Workload, Operation, IPAddress, CountryCode, Details = substring(tostring(Details), 0, 200)
| order by Timestamp desc
```

Extend it with queries 5, 9 and 13 filtered on the same caller, because role assignments, Sentinel rules and Exchange policies are in other sources.

---

## Detection ideas

| Idea | Based on | Why |
| --- | --- | --- |
| Custom detection rule deleted or switched off | Query 3 | A rule that stops running is a blind spot |
| New alert suppression rule, or a disabled one | Query 4 | Quietest way to hide a detection |
| Analytics rule deleted by anyone but the deployment pipeline | Query 5 | Detection loss, or a pipeline that changed owner |
| Offboarding package downloaded | Query 6 | Devices leaving Defender |
| Advanced feature or data retention changed | Query 6 | Weaker telemetry or investigation |
| Indicator with an allow action added | Query 7 | Exemption from detection |
| Defender role created or edited, or Defender Experts permissions granted | Query 8 | Access change |
| Security role assigned outside PIM | Query 9 | Permanent access instead of just-in-time |
| Live response session, isolation or file download without a comment | Query 10 | High-impact action with no reason |
| Many incidents resolved by one person in one hour | Query 12 | Alert hiding, or a clean-up that needs a check |
| Defender for Identity global exclusion added, or a sensor deleted | Query 8b | Coverage hole for identity attacks |
| Security for AI rule or prompt evidence collection disabled | Query 8c | Agent protection switched off |
| Anti-phishing, Safe Links or anti-malware policy or rule removed, disabled, or ZAP turned off | Query 13 | Weaker email protection |
| Tenant Allow/Block List allow entry for your own domain, a wildcard, or without notes | Query 13b | Filtering exemption |
| Admin audit logging turned off by a person | Query 13 and 17 | Audit evasion |
| Admin activity from a new IP or country | Query 14 | Stolen session or admin account |
| Configuration change outside working hours | Query 15 | Unusual timing |
| Five or more configuration changes in one hour | Query 16 | Bulk change |
| Any hit in the combined list | Query 17 | One weekly review across all sources |

## Limits of this data

- Defender audit events live in the unified audit log and reach `CloudAppEvents` with a delay. Do not expect an event the minute after the change.
- Advanced Hunting only reaches back 30 days. The Audit page in the Defender portal and Microsoft Purview keeps the records for as long as your audit retention policy says.
- Not every setting is audited. Microsoft logs only advanced features that are generally available, and not every page in Settings writes an event. A missing event does not prove nothing changed.
- Unified RBAC changes are in the `URBAC` workload, but the event holds IDs for the role and the principals, not names. Update and delete operation names were not observed.
- `IsAdminOperation` is `0` for the Defender events. Filtering on it hides everything in this file except Exchange and Entra.
- `ActorKind` is derived. Application actors in case management events use `UserType = 0`, and the preamble recognises them by name.
- The queries for suppression rules, MDE roles, data retention, offboarding, isolation, live response and Defender for Office 365 policies were not exercised in the test tenant: no matching events. Defender for Identity (partly), Security for AI, indicators (delete only), advanced features and Unified RBAC were exercised. The operation names come from the Microsoft documentation of the audit log. The `Details` column is there so you can read the real fields in your own tenant first.
- Endpoint security policies that you manage in Intune (antivirus exclusions, tamper protection, attack surface reduction) are audited in the Intune audit log, not here. Exclusions applied on the device itself show in `DeviceRegistryEvents`, not in `CloudAppEvents`.
- Defender for Endpoint, Defender for Identity and Security for AI changes appeared in `CloudAppEvents` within minutes. Tenant Allow/Block List and malware policy changes took longer: they were not there 30 minutes after the change and were there about 40 minutes later.
- Defender for Cloud Apps admin activity is thin in the test tenant: one `ConnectorDeleted` event from the `DefenderForCloud` workload. Add that workload to the preamble if you use it.
