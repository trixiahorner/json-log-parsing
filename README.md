# JSON Log Parsing
This project was designed to parse JSON-formatted logs. The primary goal was to demonstrate how to parse keys out of a dictionary and highlight its use case in cybersecurity. 

## How It Works
The program demonstrates how to process a JSON log file to extract important information:
- Parses the JSON log file to identify all malicious source IPs involved in security alerts
- Identifies critical severity alerts and extracts the associated target IPs that need immediate attention
- Displays detailed information about each critical alert for further analysis
```
import json

#extract all malicious source_ips, critical dest_ips, critical alerts
def extract_ips(data):
  malicious_ips = []
  critical_targets = []
  critical_alerts = []
  for item in data:
    malicious_ips.append(item.get("source_ip"))
    alert = item.get("alert")
    if alert.get("severity") == "critical":
      critical_targets.append(item.get("destination_ip"))
      critical_alerts.append(item)
  return malicious_ips, critical_targets, critical_alerts
  
#Open/close json file
with open('ids_log.json') as f:
  #return json object 
  data = json.load(f)

malicious_ips, critical_targets, critical_alerts = extract_ips(data)

#print all source_ips 
print("Malicious Source_IPs:")
print('\n'.join(malicious_ips))

#print dest_ips with critical severity
print("\nCritical Targets:")
print('\n'.join(critical_targets))

#print critical alerts
print("\nCritical Alerts:")
for item in critical_alerts:
  for key, val in item.items():
    if isinstance(val, dict):
      print("{}: ".format(key))
      for nested_key, nested_value in val.items():
        print("  {} : {}".format(nested_key, nested_value))
    else:
      print("{} : {}".format(key, val))
  print("\n")
```
  
## Code Walkthrough
### Opening json file 
This block opens the *'ids_log.json'* file and loads the content in the *data* variable as a list of dictionaries
```
with open('ids_log.json') as f: 
  data = json.load(f)
```

### Sample json file entry
```
{
        "timestamp": "2024-05-27T08:17:45Z",
        "source_ip": "192.168.1.11",
        "destination_ip": "10.0.0.2",
        "alert": {
            "type": "Brute Force Attack",
            "severity": "high",
            "description": "Multiple failed login attempts detected"
        }
```

### Function to Extract IPs
This function iterates over each item in *data* 
- Checks for *'source_ip'* and adds to *'malicious_ips'* list
- Accesses nested *'alert'* dictionary and checks *'severity'* key
- If *'severity'* key == "critical", it adds *'destination_ip'* to *'critical_targets'* list and adds entire alert to *'critical_alerts'* list
```
def extract_ips(data):
  malicious_ips = []
  critical_targets = []
  critical_alerts = []
  for item in data:
    malicious_ips.append(item.get("source_ip"))
    alert = item.get("alert")
    if alert.get("severity") == "critical":
      critical_targets.append(item.get("destination_ip"))
      critical_alerts.append(item)
  return malicious_ips, critical_targets, critical_alerts
```
- **malicious_ips**: list to store all source IP addresses from the alerts
- **critical_targets**: list to store destination IP addresses with "critical" severity
- **critical_alerts**: list to store entire alert entries with "critical" severity

### Printing Results
```
malicious_ips, critical_targets, critical_alerts = extract_ips(data)

#print all source_ips 
print("Malicious Source_IPs:")
print('\n'.join(malicious_ips))

#print dest_ips with critical severity
print("\nCritical Targets:")
print('\n'.join(critical_targets))

#print critical alerts
print("\nCritical Alerts:")
for item in critical_alerts:
  for key, val in item.items():
    if isinstance(val, dict):
      print("{}: ".format(key))
      for nested_key, nested_value in val.items():
        print("  {} : {}".format(nested_key, nested_value))
    else:
      print("{} : {}".format(key, val))
  print("\n")
```

## Extracting Key:Value Pairs
- Outer loop iterates over each alert in the *'critical_alerts'* list. Each **item** is a dictionary representing a critical alert
- Inner for loop iterates over each key:value pair in the **item** dictionary using the .items() method to iterate over both the keys and values at the same time
- If the value is a nested dictionary (checked using *isinstance()*), print nested key:value pairs using indented format: **'key : value'**
- Else, print each key:value pair in the format: **'key : value'**
```
for item in critical_alerts:
  for key, val in item.items():
    if isinstance(val, dict):
      print("{}: ".format(key))
      for nested_key, nested_value in val.items():
        print("  {} : {}".format(nested_key, nested_value))
    else:
      print("{} : {}".format(key, val))
  print("\n")
```

## Expected Output
![output](https://github.com/trixiahorner/json-log-parsing/blob/main/images/parse_json.png?raw=true)
