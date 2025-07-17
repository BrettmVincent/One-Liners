### 🔎 Alert summary for any given month

This query pulls security alerts from the `AlertInfo` table for the month of June 2025, filtering for a defined list of threat-related categories (e.g., Ransomware, InitialAccess, CommandAndControl, etc.). It extracts key fields like time generated, alert ID, title, category, severity, service source, and detection source—providing a structured overview to support monthly threat use-case reporting.

```kql
let Alert_Categories = dynamic([
    "AccountCompromise",
    "ActiveDirectory",
    "AttackSimulation",
    "Audit",
    "CloudAppSecurity",
    "CommandAndControl",
    "CredentialAccess",
    "CustomDetection",
    "DefenseEvasion",
    "Discovery",
    "Execution",
    "Exploit",
    "Exfiltration",
    "Impact",
    "InitialAccess",
    "LateralMovement",
    "Malware",
    "Persistence",
    "PrivilegeEscalation",
    "Ransomware",
    "Reconnaissance",
    "SuspiciousActivity",
    "ThreatIntelligence",
    "UnwantedSoftware",
    "Vulnerability",
    "WebDelivery"
]);
AlertInfo
| where TimeGenerated between (datetime(2025-06-01)..datetime(2025-06-30)) // Adjust the dated based on the timeframe you are looking for.
| where Category has_any (Alert_Categories)
| project TimeGenerated, AlertId, Title, Category, Severity, ServiceSource, DetectionSource
//| summarize count() by Category
```

> [!NOTE]
> **Retention Period Limitations:** <br>The data returned by this query is limited by the retention period configured in your security solution (typically 30, 90, or 180 days, depending on licensing and settings). If the query's timeframe (here, June 2025) exceeds that retention window, older alerts may no longer exist in the system and thus won’t appear in results. This means historical trends beyond the retention period cannot be accurately analyzed. To avoid missing data, always confirm the retention policy and adjust your query timeframe accordingly.
