from datetime import timedelta
from colorama import Fore
import pandas as pd

def query_devicelogonevents(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller):
    # --- NEW: map AlertInfo -> SecurityAlert and set correct fields ---
    if table_name in ("AlertInfo", "SecurityAlert"):
        # Your threats are in the SecurityAlert table, not AlertInfo
        table_name = "SecurityAlert"
        # Use columns that actually exist in SecurityAlert
        fields = "TimeGenerated, DisplayName, AlertName, AlertSeverity, Description, ProviderName"

    # tables that actually have a DeviceName column
    tables_with_device_name = {
        "DeviceProcessEvents",
        "DeviceNetworkEvents",
        "DeviceLogonEvents",
        "DeviceFileEvents",
        "DeviceRegistryEvents",
    }

    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'''{table_name}
| where FlowType_s == "MaliciousFlow"
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "AzureActivity" and caller:
        user_query = f'''{table_name}
| where Caller startswith "{caller}"
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "SigninLogs" and caller:
        user_query = f'''{table_name}
| where UserPrincipalName startswith "{caller}"
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name in tables_with_device_name and device_name:
        user_query = f'''{table_name}
| where DeviceName startswith "{device_name}"
| project {fields}
| order by TimeGenerated desc'''
        
    else:
        # SecurityAlert, AlertEvidence, anything without DeviceName / special filters
        user_query = f'''{table_name}
| project {fields}
| order by TimeGenerated desc'''
        
    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")

    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Worksapce ID: '{workspace_id}'...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours)
    )

    table = response.tables[0]
    print(f"{Fore.WHITE}Log Analytics query returned {len(table.rows)} record(s).\n")

    columns = table.columns
    rows = table.rows

    df = pd.DataFrame(rows, columns=columns)
    results = df.to_csv(index=False)

    return results
