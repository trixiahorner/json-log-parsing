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
    print("{} : {}".format(key, val))
  print("\n")

  

