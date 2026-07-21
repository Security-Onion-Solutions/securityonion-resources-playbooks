# Playbook Field Inventory — Sigma Playbooks

Catalogue of every field name used in the playbook question queries, grouped by
logsource category, with the SO/ECS field each converts to. ECS targets are
derived by converting a probe rule through the deployed playbook-question stack
(`sigma_so_pipeline` + `sigma_playbook_pipeline` + `windows-logsources` +
`ecs_windows` → security_onion backend) — the same composition SOC uses, so
`.caseless`-routed fields show their routed target.

**Regenerate:** `python3 5_validate/gen_field_inventory.py` (authoring pipeline root)

## Conventions

- Question queries use **Sigma-spec field names** (`Image`, `CommandLine`, `ImageLoaded`,
  `EventID`, `Channel`, `ParentName`, …); the pipeline maps them to ECS at convert time.
- The only bare ECS field names permitted are the **platform floor** (below) — host scoping
  and prior-detection lookup, which have no Sigma-taxonomy expression.
- `winlog.event_data.<X>` should be written as bare `<X>` (Windows EventLog attribute).

## Platform floor — ECS fields with no Sigma-spec equivalent (allowed)

| field | role |
|---|---|
| `host.name` | host-scope clause (`%hostname%`) |
| `rule.uuid` | precursor-detection meta query (prior SO detections) |
| `rule.name` | precursor-detection meta query |
| `event.module` | precursor-detection meta query (`event.module: sigma`) |
| `event.severity_label` | precursor-detection meta query |

## Fields by logsource category

### `(none)`  (166 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `process.Ext.api.name` | `process.Ext.api.name` | 42 | 42 |
| `document_id` | `_id` | 68 | 0 |
| `event_data.host.name` | `event_data.host.name` | 0 | 68 |
| `host.name`  _(floor)_ | `host.name` | 62 | 1 |
| `event_data.source.ip` | `event_data.source.ip` | 18 | 35 |
| `event.dataset` | `event.dataset` | 42 | 0 |
| `Image` | `process.executable.caseless` | 0 | 41 |
| `EventID` | `EventID` | 21 | 17 |
| `rule.name`  _(floor)_ | `rule.name` | 1 | 34 |
| `event_data.tags` | `event_data.tags` | 34 | 0 |
| `process.executable` | `process.executable.caseless` | 3 | 19 |
| `Channel` | `Channel` | 21 | 0 |
| `message` | `message` | 0 | 21 |
| `related.ip` | `related.ip` | 17 | 0 |
| `winlog.user_data.ProviderName` | `winlog.user_data.ProviderName` | 0 | 15 |
| `winlog.user_data.Query` | `winlog.user_data.Query` | 0 | 15 |
| `winlog.user_data.CONSUMER` | `winlog.user_data.CONSUMER` | 0 | 14 |
| `winlog.user_data.NamespaceName` | `winlog.user_data.NamespaceName` | 0 | 12 |
| `winlog.user_data.ESS` | `winlog.user_data.ESS` | 0 | 8 |
| `event_data.logdata.USERNAME` | `event_data.logdata.USERNAME` | 0 | 7 |
| `User` | `user.name` | 0 | 6 |
| `event_data.logdata.PASSWORD` | `event_data.logdata.PASSWORD` | 0 | 6 |
| `winlog.user_data.HostProcess` | `winlog.user_data.HostProcess` | 0 | 6 |
| `Target.process.executable` | `Target.process.executable` | 0 | 3 |
| `event_data.logdata.FILENAME` | `event_data.logdata.FILENAME` | 0 | 2 |
| `event_data.logdata.NTP CMD` | `CMD` | 0 | 2 |
| `event_data.logdata.PATH` | `event_data.logdata.PATH` | 0 | 2 |
| `event_data.user.name` | `event_data.user.name` | 0 | 2 |
| `GrantedAccess` | `GrantedAccess` | 0 | 1 |
| `ProcessGuid` | `process.entity_id` | 0 | 1 |
| `event_data.idh.password_submitted` | `event_data.idh.password_submitted` | 0 | 1 |
| `event_data.logdata.ARGS` | `event_data.logdata.ARGS` | 0 | 1 |
| `event_data.logdata.AUDITACTION` | `event_data.logdata.AUDITACTION` | 0 | 1 |
| `event_data.logdata.CMD` | `event_data.logdata.CMD` | 0 | 1 |
| `event_data.logdata.COMMUNITY_STRING` | `event_data.logdata.COMMUNITY_STRING` | 0 | 1 |
| `event_data.logdata.DOMAIN` | `event_data.logdata.DOMAIN` | 0 | 1 |
| `event_data.logdata.HEADERS` | `event_data.logdata.HEADERS` | 0 | 1 |
| `event_data.logdata.HOST` | `event_data.logdata.HOST` | 0 | 1 |
| `event_data.logdata.MODE` | `event_data.logdata.MODE` | 0 | 1 |
| `event_data.logdata.OPCODE` | `event_data.logdata.OPCODE` | 0 | 1 |
| `event_data.logdata.REMOTEVERSION` | `event_data.logdata.REMOTEVERSION` | 0 | 1 |
| `event_data.logdata.REPO` | `event_data.logdata.REPO` | 0 | 1 |
| `event_data.logdata.REQUESTS` | `event_data.logdata.REQUESTS` | 0 | 1 |
| `event_data.logdata.SESSION` | `event_data.logdata.SESSION` | 0 | 1 |
| `event_data.logdata.SHARENAME` | `event_data.logdata.SHARENAME` | 0 | 1 |
| `event_data.logdata.SKIN` | `event_data.logdata.SKIN` | 0 | 1 |
| `event_data.logdata.USER` | `event_data.logdata.USER` | 0 | 1 |
| `event_data.logdata.USERAGENT` | `event_data.logdata.USERAGENT` | 0 | 1 |
| `event_data.logdata.VNC_Client_Response` | `event_data.logdata.VNC_Client_Response` | 0 | 1 |
| `event_data.logdata.VNC_Password` | `event_data.logdata.VNC_Password` | 0 | 1 |
| `event_data.logdata.VNC_Server_Challenge` | `event_data.logdata.VNC_Server_Challenge` | 0 | 1 |
| `process.Ext.api.summary` | `process.Ext.api.summary` | 0 | 1 |
| `process.name` | `process.name` | 0 | 1 |

### `alert`  (2035 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `event.module`  _(floor)_ | `event.module` | 2031 | 0 |
| `host.name`  _(floor)_ | `host.name` | 1847 | 184 |
| `rule.uuid`  _(floor)_ | `rule.uuid` | 170 | 1846 |
| `rule.name`  _(floor)_ | `rule.name` | 4 | 1903 |
| `event.severity_label`  _(floor)_ | `event.severity_label` | 0 | 1898 |
| `User` | `user.name` | 0 | 117 |
| `user.name` | `user.name` | 10 | 0 |
| `document_id` | `_id` | 2 | 0 |
| `related.ip` | `related.ip` | 2 | 0 |
| `CommandLine` | `process.command_line.caseless` | 0 | 1 |
| `Image` | `process.executable.caseless` | 0 | 1 |
| `ParentImage` | `process.parent.executable.caseless` | 0 | 1 |
| `file.path` | `file.path.caseless` | 0 | 1 |
| `hostname` | `event_data.host.name` | 0 | 1 |
| `rule.level` | `rule.level` | 0 | 1 |
| `rule.type` | `event.module` | 0 | 1 |

### `application`  (22 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 6 | 17 |
| `Provider_Name` | `winlog.provider_name` | 4 | 18 |
| `host.name`  _(floor)_ | `host.name` | 22 | 0 |
| `Data` | `winlog.event_data.Data` | 2 | 8 |
| `Message` | `winlog.event_data.Message` | 0 | 5 |
| `Provider` | `winlog.event_data.Provider` | 1 | 2 |
| `Channel` | `winlog.channel` | 2 | 0 |
| `User` | `user.name` | 0 | 2 |
| `SourceIp` | `source.ip` | 0 | 1 |
| `param1` | `winlog.event_data.param1` | 0 | 1 |
| `param2` | `winlog.event_data.param2` | 0 | 1 |
| `source` | `winlog.event_data.source` | 1 | 0 |

### `auth`  (3 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `User` | `user.name` | 3 | 1 |
| `event.action` | `event.action` | 3 | 0 |
| `event.outcome` | `event.outcome` | 2 | 1 |
| `source.ip` | `source.ip` | 0 | 3 |
| `tags` | `tags` | 3 | 0 |
| `host.name`  _(floor)_ | `host.name` | 0 | 2 |

### `authentication`  (2 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `LogonType` | `winlog.event_data.LogonType` | 0 | 2 |
| `User` | `user.name` | 0 | 2 |
| `host.name`  _(floor)_ | `host.name` | 2 | 0 |
| `SourceIp` | `source.ip` | 0 | 1 |
| `SourceNetworkAddress` | `winlog.event_data.SourceNetworkAddress` | 0 | 1 |

### `certificateservicesclient-lifecycle-system`  (1 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 1 | 0 |
| `Subject` | `winlog.event_data.Subject` | 0 | 1 |
| `UserData` | `winlog.event_data.UserData` | 0 | 1 |
| `host.name`  _(floor)_ | `host.name` | 1 | 0 |

### `dns_query`  (180 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `QueryName` | `dns.question.name` | 136 | 135 |
| `Image` | `process.executable.caseless` | 42 | 138 |
| `host.name`  _(floor)_ | `host.name` | 144 | 36 |
| `User` | `user.name` | 0 | 7 |
| `dns.resolved_ip` | `dns.resolved_ip` | 1 | 2 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 1 |
| `QueryResults` | `winlog.event_data.QueryResults` | 0 | 1 |
| `QueryType` | `winlog.event_data.QueryType` | 0 | 1 |

### `driver_load`  (65 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `ImageLoaded` | `dll.path` | 47 | 42 |
| `host.name`  _(floor)_ | `host.name` | 54 | 13 |
| `Hashes` | `dll.hash.sha256` | 4 | 37 |
| `Signature` | `dll.code_signature.subject_name` | 0 | 39 |
| `SignatureStatus` | `dll.code_signature.status` | 0 | 28 |
| `Image` | `process.executable.caseless` | 0 | 23 |
| `Signed` | `dll.code_signature.exists` | 0 | 18 |
| `User` | `user.name` | 0 | 2 |

### `file_activity`  (1791 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetFilename` | `file.path.caseless` | 705 | 1571 |
| `Image` | `process.executable.caseless` | 265 | 1691 |
| `EventType` | `event.action` | 0 | 1348 |
| `host.name`  _(floor)_ | `host.name` | 971 | 212 |
| `ProcessGuid` | `process.entity_id` | 822 | 2 |
| `ParentProcessGuid` | `process.parent.entity_id` | 812 | 0 |
| `process.code_signature.subject_name` | `process.code_signature.subject_name` | 0 | 422 |
| `process.code_signature.trusted` | `process.code_signature.trusted` | 0 | 422 |
| `User` | `user.name` | 8 | 267 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 8 |
| `ParentImage` | `process.parent.executable.caseless` | 0 | 2 |
| `CreationUtcTime` | `winlog.event_data.CreationUtcTime` | 0 | 1 |
| `SourceFilename` | `winlog.event_data.SourceFilename` | 0 | 1 |

### `file_delete`  (63 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetFilename` | `file.path.caseless` | 57 | 22 |
| `host.name`  _(floor)_ | `host.name` | 24 | 37 |
| `Image` | `process.executable.caseless` | 34 | 25 |
| `User` | `user.name` | 13 | 16 |
| `ProcessGuid` | `process.entity_id` | 2 | 1 |
| `ParentProcessGuid` | `process.parent.entity_id` | 1 | 0 |

### `file_event`  (1932 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetFilename` | `file.path.caseless` | 1860 | 1255 |
| `host.name`  _(floor)_ | `host.name` | 1192 | 704 |
| `Image` | `process.executable.caseless` | 589 | 1275 |
| `User` | `user.name` | 199 | 201 |
| `ProcessGuid` | `process.entity_id` | 50 | 61 |
| `CommandLine` | `winlog.event_data.CommandLine` | 12 | 1 |
| `ParentProcessGuid` | `process.parent.entity_id` | 13 | 0 |
| `EventType` | `event.action` | 0 | 10 |
| `ParentImage` | `process.parent.executable.caseless` | 9 | 0 |
| `CreationUtcTime` | `winlog.event_data.CreationUtcTime` | 3 | 0 |
| `ParentCommandLine` | `process.parent.command_line.caseless` | 3 | 0 |
| `hostname` | `winlog.event_data.hostname` | 0 | 2 |
| `ProcessId` | `process.pid` | 0 | 1 |
| `file.path` | `file.path.caseless` | 0 | 1 |

### `file_rename`  (4 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetFilename` | `file.path.caseless` | 4 | 1 |
| `SourceFilename` | `file.Ext.original.path` | 3 | 1 |
| `host.name`  _(floor)_ | `host.name` | 1 | 3 |
| `Image` | `process.executable.caseless` | 2 | 1 |
| `User` | `user.name` | 1 | 0 |

### `image_load`  (1082 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `ImageLoaded` | `dll.path` | 624 | 796 |
| `host.name`  _(floor)_ | `host.name` | 721 | 109 |
| `Image` | `process.executable.caseless` | 338 | 465 |
| `Signed` | `dll.code_signature.exists` | 51 | 571 |
| `Signature` | `dll.code_signature.subject_name` | 10 | 535 |
| `SignatureStatus` | `dll.code_signature.status` | 12 | 408 |
| `Hashes` | `dll.hash.sha256` | 3 | 334 |
| `ProcessGuid` | `process.entity_id` | 280 | 11 |
| `User` | `user.name` | 0 | 59 |
| `CommandLine` | `winlog.event_data.CommandLine` | 2 | 20 |
| `OriginalFileName` | `file.pe.original_file_name` | 8 | 5 |
| `Description` | `file.pe.description` | 2 | 2 |
| `ParentProcessGuid` | `process.parent.entity_id` | 1 | 0 |

### `network_connection`  (1165 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `DestinationPort` | `destination.port` | 290 | 1034 |
| `DestinationIp` | `destination.ip` | 301 | 844 |
| `Image` | `process.executable.caseless` | 516 | 568 |
| `host.name`  _(floor)_ | `host.name` | 1023 | 46 |
| `Initiated` | `network.initiated` | 390 | 273 |
| `DestinationHostname` | `destination.domain` | 5 | 420 |
| `User` | `user.name` | 3 | 196 |
| `ProcessGuid` | `process.entity_id` | 130 | 2 |
| `SourceIp` | `source.ip` | 6 | 62 |
| `CommandLine` | `winlog.event_data.CommandLine` | 10 | 13 |
| `SourcePort` | `source.port` | 7 | 7 |
| `ParentImage` | `process.parent.executable.caseless` | 6 | 1 |
| `ParentProcessGuid` | `process.parent.entity_id` | 5 | 0 |
| `Protocol` | `network.transport` | 4 | 1 |
| `SourceHostname` | `source.domain` | 3 | 0 |
| `SourceIsIpv6` | `winlog.event_data.SourceIsIpv6` | 2 | 1 |
| `ParentName` | `winlog.event_data.ParentName` | 2 | 0 |
| `community_id` | `winlog.event_data.community_id` | 0 | 1 |
| `destination.ip` | `destination.ip` | 0 | 1 |
| `destination.port` | `destination.port` | 0 | 1 |
| `network.initiated` | `network.initiated` | 0 | 1 |
| `source.ip` | `source.ip` | 0 | 1 |
| `source.port` | `source.port` | 0 | 1 |

### `powershell`  (219 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `ScriptBlockText` | `powershell.file.script_block_text` | 1 | 219 |
| `EventID` | `event.code` | 219 | 0 |
| `Path` | `winlog.event_data.Path` | 0 | 219 |
| `ScriptBlockId` | `powershell.file.script_block_id` | 0 | 219 |
| `host.name`  _(floor)_ | `host.name` | 219 | 0 |

### `process_creation`  (21976 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `Image` | `process.executable.caseless` | 7610 | 9704 |
| `host.name`  _(floor)_ | `host.name` | 7850 | 7698 |
| `CommandLine` | `process.command_line.caseless` | 5918 | 9498 |
| `ProcessGuid` | `process.entity_id` | 7661 | 12 |
| `User` | `user.name` | 2942 | 3887 |
| `ParentImage` | `process.parent.executable.caseless` | 1851 | 4871 |
| `OriginalFileName` | `process.pe.original_file_name` | 2658 | 955 |
| `ParentName` | `process.parent.name` | 2850 | 0 |
| `ParentCommandLine` | `process.parent.command_line.caseless` | 293 | 1134 |
| `CurrentDirectory` | `process.working_directory` | 46 | 1230 |
| `ParentProcessGuid` | `process.parent.entity_id` | 659 | 6 |
| `Hashes` | `process.hash.sha256` | 201 | 407 |
| `Description` | `process.pe.description` | 322 | 79 |
| `IntegrityLevel` | `process.Ext.token.integrity_level_name` | 163 | 124 |
| `Product` | `process.pe.product` | 219 | 49 |
| `Company` | `process.pe.company` | 87 | 21 |
| `FileVersion` | `process.pe.file_version` | 14 | 4 |
| `LogonId` | `winlog.event_data.LogonId` | 8 | 3 |
| `ParentUser` | `winlog.event_data.ParentUser` | 8 | 2 |
| `GrandParentImage` | `winlog.event_data.GrandParentImage` | 6 | 2 |
| `Provider_Name` | `winlog.provider_name` | 3 | 0 |
| `Signed` | `file.code_signature.signed` | 0 | 3 |
| `Destination` | `process.executable.caseless` | 0 | 2 |
| `EventID` | `event.code` | 1 | 1 |
| `Signature` | `winlog.event_data.Signature` | 0 | 2 |
| `SignatureStatus` | `file.code_signature.status` | 0 | 2 |
| `hostname` | `winlog.event_data.hostname` | 0 | 2 |
| `NewProcessName` | `process.executable.caseless` | 0 | 1 |
| `SubjectUserName` | `winlog.event_data.SubjectUserName` | 0 | 1 |
| `TokenElevationType` | `winlog.event_data.TokenElevationType` | 0 | 1 |
| `event.action` | `event.action` | 0 | 1 |

### `ps_script`  (290 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `host.name`  _(floor)_ | `host.name` | 180 | 143 |
| `ScriptBlockText` | `powershell.file.script_block_text` | 100 | 95 |
| `powershell.file.script_block_id` | `powershell.file.script_block_id` | 99 | 0 |
| `Path` | `winlog.event_data.Path` | 3 | 89 |
| `user.name` | `user.name` | 0 | 92 |
| `log.level` | `log.level` | 0 | 61 |
| `User` | `user.name` | 33 | 0 |
| `powershell.sequence` | `powershell.sequence` | 0 | 33 |
| `powershell.total` | `powershell.total` | 0 | 33 |
| `powershell.file.script_block_hash` | `powershell.file.script_block_hash` | 30 | 0 |

### `registry_event`  (11 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `Image` | `process.executable.caseless` | 10 | 4 |
| `TargetObject` | `registry.path` | 10 | 0 |
| `host.name`  _(floor)_ | `host.name` | 6 | 4 |
| `User` | `user.name` | 0 | 4 |
| `Details` | `winlog.event_data.Details` | 3 | 0 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 2 |
| `EventType` | `winlog.event_data.EventType` | 0 | 1 |
| `ParentProcessGuid` | `process.parent.entity_id` | 1 | 0 |
| `ProcessGuid` | `process.entity_id` | 1 | 0 |
| `TargetRegistryKey` | `winlog.event_data.TargetRegistryKey` | 0 | 1 |
| `TargetRegistryValueName` | `winlog.event_data.TargetRegistryValueName` | 0 | 1 |
| `TargetRegistryValueType` | `winlog.event_data.TargetRegistryValueType` | 0 | 1 |

### `registry_set`  (2286 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `TargetObject` | `registry.path` | 1943 | 1474 |
| `host.name`  _(floor)_ | `host.name` | 1971 | 488 |
| `Image` | `process.executable.caseless` | 13 | 1959 |
| `Details` | `registry.data.strings` | 26 | 1617 |
| `process.code_signature.subject_name` | `process.code_signature.subject_name` | 0 | 754 |
| `process.code_signature.trusted` | `process.code_signature.trusted` | 0 | 754 |
| `User` | `user.name` | 3 | 554 |
| `ProcessGuid` | `process.entity_id` | 76 | 2 |
| `EventType` | `event.action` | 1 | 6 |
| `NewName` | `winlog.event_data.NewName` | 0 | 4 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 2 |
| `EventID` | `event.code` | 0 | 1 |

### `security`  (248 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 238 | 109 |
| `host.name`  _(floor)_ | `host.name` | 194 | 37 |
| `SubjectUserName` | `user.name` | 7 | 140 |
| `TargetUserName` | `winlog.event_data.TargetUserName` | 28 | 93 |
| `LogonType` | `winlog.event_data.LogonType` | 13 | 84 |
| `IpAddress` | `source.ip` | 1 | 90 |
| `ServiceName` | `service.name` | 0 | 33 |
| `TaskName` | `winlog.event_data.TaskName` | 0 | 32 |
| `ObjectName` | `winlog.event_data.ObjectName` | 6 | 21 |
| `PrivilegeList` | `winlog.event_data.PrivilegeList` | 1 | 26 |
| `ServiceFileName` | `winlog.event_data.ServiceFileName` | 0 | 24 |
| `ProcessName` | `process.executable.caseless` | 0 | 18 |
| `AccessMask` | `winlog.event_data.AccessMask` | 0 | 15 |
| `ShareName` | `winlog.event_data.ShareName` | 5 | 7 |
| `SubjectLogonId` | `winlog.logon.id` | 0 | 12 |
| `RelativeTargetName` | `winlog.event_data.RelativeTargetName` | 5 | 6 |
| `TaskContent` | `winlog.event_data.TaskContent` | 0 | 10 |
| `ServiceAccount` | `winlog.event_data.ServiceAccount` | 0 | 8 |
| `TicketEncryptionType` | `winlog.event_data.TicketEncryptionType` | 3 | 5 |
| `ServiceType` | `winlog.event_data.ServiceType` | 0 | 7 |
| `ObjectDN` | `winlog.event_data.ObjectDN` | 1 | 5 |
| `User` | `user.name` | 0 | 6 |
| `WorkstationName` | `source.domain` | 0 | 6 |
| `AttributeLDAPDisplayName` | `winlog.event_data.AttributeLDAPDisplayName` | 1 | 2 |
| `AuthenticationPackageName` | `winlog.event_data.AuthenticationPackageName` | 0 | 3 |
| `Computer` | `winlog.event_data.Computer` | 3 | 0 |
| `MemberName` | `winlog.event_data.MemberName` | 0 | 3 |
| `ObjectType` | `winlog.event_data.ObjectType` | 0 | 3 |
| `Properties` | `winlog.event_data.Properties` | 2 | 1 |
| `ServiceStartType` | `winlog.event_data.ServiceStartType` | 0 | 3 |
| `SubjectDomainName` | `user.domain` | 0 | 3 |
| `AuditPolicyChanges` | `winlog.event_data.AuditPolicyChanges` | 0 | 2 |
| `NewProcessName` | `process.executable.caseless` | 1 | 1 |
| `TargetServerName` | `winlog.event_data.TargetServerName` | 0 | 2 |
| `AttributeValue` | `winlog.event_data.AttributeValue` | 0 | 1 |
| `CallerProcessName` | `winlog.event_data.CallerProcessName` | 0 | 1 |
| `Channel` | `winlog.channel` | 0 | 1 |
| `ComputerName` | `winlog.computer_name` | 1 | 0 |
| `Image` | `process.executable.caseless` | 0 | 1 |
| `ObjectClass` | `winlog.event_data.ObjectClass` | 0 | 1 |
| `ObjectValueName` | `winlog.event_data.ObjectValueName` | 0 | 1 |
| `ParentProcessName` | `process.parent.name` | 0 | 1 |
| `ProcessId` | `process.pid` | 0 | 1 |
| `SamAccountName` | `winlog.event_data.SamAccountName` | 0 | 1 |
| `TokenElevationType` | `winlog.event_data.TokenElevationType` | 0 | 1 |
| `rule.name`  _(floor)_ | `rule.name` | 0 | 1 |
| `rule.uuid`  _(floor)_ | `rule.uuid` | 0 | 1 |
| `user.name` | `user.name` | 0 | 1 |
| `winlog.event_data.SubjectUserName` | `winlog.event_data.SubjectUserName` | 0 | 1 |

### `system`  (44 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 43 | 5 |
| `host.name`  _(floor)_ | `host.name` | 42 | 2 |
| `ServiceName` | `winlog.event_data.ServiceName` | 0 | 42 |
| `ImagePath` | `winlog.event_data.ImagePath` | 1 | 40 |
| `AccountName` | `user.name` | 0 | 34 |
| `StartType` | `winlog.event_data.StartType` | 0 | 32 |
| `ServiceType` | `winlog.event_data.ServiceType` | 0 | 13 |
| `Provider_Name` | `winlog.provider_name` | 1 | 1 |
| `ServiceFileName` | `winlog.event_data.ServiceFileName` | 0 | 1 |
| `User` | `user.name` | 0 | 1 |

### `taskscheduler`  (1 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 0 | 1 |
| `TaskName` | `winlog.event_data.TaskName` | 0 | 1 |
| `host.name`  _(floor)_ | `host.name` | 1 | 0 |

### `wmi`  (19 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 17 | 17 |
| `host.name`  _(floor)_ | `host.name` | 17 | 2 |
| `winlog.user_data.CONSUMER` | `winlog.user_data.CONSUMER` | 0 | 14 |
| `message` | `winlog.event_data.message` | 0 | 13 |
| `winlog.user_data.Query` | `winlog.user_data.Query` | 0 | 13 |
| `winlog.user_data.ESS` | `winlog.user_data.ESS` | 0 | 8 |
| `winlog.user_data.NamespaceName` | `winlog.user_data.NamespaceName` | 0 | 8 |
| `winlog.user_data.ProviderName` | `winlog.user_data.ProviderName` | 0 | 8 |
| `User` | `user.name` | 0 | 3 |
| `Operation` | `winlog.event_data.Operation` | 0 | 2 |
| `CommandLine` | `winlog.event_data.CommandLine` | 0 | 1 |
| `winlog.user_data.ClientMachine` | `winlog.user_data.ClientMachine` | 0 | 1 |
| `winlog.user_data.HostProcess` | `winlog.user_data.HostProcess` | 0 | 1 |

### `wmi_event`  (3 questions)

| sigma field | → SO/ECS field | sel | proj |
|---|---|---|---|
| `EventID` | `event.code` | 2 | 1 |
| `host.name`  _(floor)_ | `host.name` | 2 | 1 |
| `winlog.user_data.CONSUMER` | `winlog.user_data.CONSUMER` | 0 | 2 |
| `Consumer` | `winlog.event_data.Consumer` | 0 | 1 |
| `EventType` | `winlog.event_data.EventType` | 0 | 1 |
| `Operation` | `winlog.event_data.Operation` | 0 | 1 |
| `Query` | `winlog.event_data.Query` | 0 | 1 |
| `User` | `user.name` | 0 | 1 |
| `message` | `winlog.event_data.message` | 0 | 1 |
| `winlog.user_data.ESS` | `winlog.user_data.ESS` | 0 | 1 |
| `winlog.user_data.NamespaceName` | `winlog.user_data.NamespaceName` | 0 | 1 |
| `winlog.user_data.Query` | `winlog.user_data.Query` | 0 | 1 |
