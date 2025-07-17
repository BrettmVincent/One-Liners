This KQL query retrieves a list of onboarded devices whose names start with `"corp-edge"` and shows **only the most recent record** for each device. From that latest record, it extracts key information such as:

- ✅ Onboarding status  
- 🔐 Exclusion details  
- 👤 Logged-on user  
- ⏱️ Last seen timestamp

---

**In essence:**  
You're pulling a clean, one-line summary per device showing the most recent status, who was last logged on, and when the device was last seen - useful for quickly assessing the current state of specific endpoints in your environment.

```kql
DeviceInfo
| where DeviceName startswith "corp-edge" // Replace this with the starting prefix of your device names
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, OnboardingStatus, LoggedOnUsers, IsExcluded, ExclusionReason) by DeviceName
| extend LoggedOnUser = tostring(LoggedOnUsers[0].UserName)
| project DeviceName,
          OnboardingStatus,
          LoggedOnUser,
          IsExcluded,
          ExclusionReason,
          LastSeen = Timestamp
