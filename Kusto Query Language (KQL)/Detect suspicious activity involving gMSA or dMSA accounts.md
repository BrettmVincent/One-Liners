## 🔍 **Detection: Suspicious Activity Involving gMSA/dMSA Accounts**

This Microsoft Defender KQL query monitors for suspicious behaviour around **Group Managed Service Accounts (gMSA)** and **Distributed Managed Service Accounts (dMSA)**.  

### 🎯 What it Detects:
- 🗝️ **Access to KDS Root Key** – spotting attackers prepping for MSA abuse  
- 🧠 **LDAP Queries** – likely MSA enumeration
- 🔐 **Kerberos Failures** – signs of brute-force attempts  
- 💻 **Suspicious Device Logins** – logins from unknown/blank devices  

All logic filters for accounts ending in **`$`**, which indicates service accounts.

```kql
union
(
    AuditLogs
    | where OperationName == "Accessed Directory Object"
    | where TargetResources has "msKds-RootKey"
    | project TimeGenerated, Identity, OperationName, TargetResources, Result
),
(
    IdentityDirectoryEvents
    | where Type == "LDAP Query"
    | where AdditionalFields contains "msDS-ManagedServiceAccount"
    | project TimeGenerated, AccountName, Query = AdditionalFields, SourceIPAddress = IPAddress
),
(
    SecurityEvent
    | where EventID in (4768, 4769)
    | where Status != "0x0"
    | join kind=inner (
        IdentityInfo
        | where Type == "ServiceAccount"
        | where AccountName endswith "$"
        | project AccountName
      ) on $left.TargetUserName == $right.AccountName
    | project TimeGenerated, TargetUserName, ClientIPAddress, Status
    | summarize FailureCount = count() by TargetUserName, ClientIPAddress, bin(TimeGenerated, 1h)
    | where FailureCount > 10
    | project TimeGenerated=bin(TimeGenerated, 1h), AccountName=TargetUserName, IPAddress=ClientIPAddress, FailureCount
),
(
    SigninLogs
    | join kind=inner (
        IdentityInfo
        | where Type == "ServiceAccount"
        | where AccountName endswith "$"
        | project AccountName
      ) on $left.UserPrincipalName == $right.AccountName
    | where DeviceDetail contains "Unknown" or isnull(DeviceDetail)
    | project TimeGenerated, AccountName, DeviceDetail, IPAddress
)
| sort by TimeGenerated desc
```
>[!TIP]
>Combine this with alert logic or dashboards to continuously monitor and triage high-risk MSA activity.
