import os
# import glob
import pandas as pd
from datetime import datetime
from collections import Counter

# Changes the cwd to the directory of the file
current_directory = os.path.dirname(__file__)
os.chdir(current_directory)

# this selects the necessary files to pull in
for filename in os.listdir(current_directory):
    if filename.startswith("formatted_cynerio_vulns"):
        os.remove(filename)
    elif filename.startswith("cynerio_vulns"):
        cynerio_report_no_id = pd.read_csv(filename, keep_default_na=False)
    elif filename.startswith("cynerio_iomt_report"):
        asset_report = pd.read_csv(filename, keep_default_na=False)
        # asset_report.rename(columns={"Display name": "Display Name"})

# renaming columns to match for custom_identifer function
cynerio_report_no_id.rename(columns={"IP": "IP Address"}, inplace=True)
cynerio_report_no_id.rename(columns={"Display name": "Display Name"}, inplace=True)

def custom_identifier(row):
    return f"{str(row["Vendor"])}-{str(row["Model"])}-{str(row["MAC"])}-{str(row["Display Name"])}-{str(row["IP Address"])}"

cynerio_report_no_id["Custom Identifier"] = cynerio_report_no_id.apply(custom_identifier, axis=1) #KeyError: 'Display Name
asset_report["Custom Identifier"] = asset_report.apply(custom_identifier, axis=1)

assetID_list = asset_report[["Asset ID", "Custom Identifier"]]
cynerio_report = pd.merge(cynerio_report_no_id, assetID_list, on="Custom Identifier", how="inner")

def create_risk_instanceID(row):
    return f"{row["ID"]}"

def create_issuetype(row):
    return "Vulnerability"

def current_owner(row):
    return model_assignments[row["Model"]]

def create_priority(row):
    if row["CVSS"] >= 9.0 and row["Risk Level"] == "Critical":
        return "1-Immediate"
    elif row["Risk Level"] == "Critical":
        return "2-Critical"
    elif row["Risk Level"] == "High":
        return "3-Important"
    elif row["Risk Level"] == "Medium":
        return "4-Standard"
    else:
        return "5-Low"

def create_summary(row):
    return f"Cynerio flagged this device as vulnerable to {str(row["Name"])}. {str(row["Description"])}"

def create_cve_model(row):
    if not row["Model"] or row["Model"] == "N/A":
        return
    else:
        return f"{row["Name"]}-{str(row["Model"])}"

def create_os_version(row):
        return row["OS"]

def create_alertURL(row):
    return f"https://us.app.cynerio.com/ui/Mercy/asset/risks/{str(row["Asset ID"])}"

def create_recommendedactions(row):
    return """Update each applicable risk instance (Vuln + Make + Model) in Cynerio with the CIM number of this ticket.

Investigate the impact of the CVE on the model. Find the answers for these questions:
    - Is the model vulnerable to the CVE? 
    - If so, is there a validated patch (or compensating control) that can be applied?
        
Follow the vulnerability management workflow after gathering the answers."""

def create_severity(row):
    if row["CVSS"] >= 9.0:
        return "Critical"
    elif row["CVSS"] <= 8.9 and row["CVSS"] >=7.0:
        return "High"
    elif row["CVSS"] <= 6.9 and row["CVSS"] >=4.0:
        return "Medium"
    elif row["CVSS"] <= 3.9 and row["CVSS"] >=.1:
        return "Low"

def create_alert_description(row):
    if "CVE-" in row["Name"]:
        return f"{str(row["Description"])} \n\nhttps://nvd.nist.gov/vuln/detail/{str(row["Name"])}"
    else:
        return row["Description"]

cynerio_report["Issue Type"] = cynerio_report.apply(create_issuetype, axis=1)
cynerio_report["Severity"] = cynerio_report.apply(create_severity, axis=1)
cynerio_report["Priority"] = cynerio_report.apply(create_priority, axis=1)
cynerio_report["Summary"] = cynerio_report.apply(create_summary, axis=1)
cynerio_report["Risk Instance ID"] = cynerio_report.apply(create_risk_instanceID, axis=1)
cynerio_report["CVE & Model"] = cynerio_report.apply(create_cve_model, axis=1)
cynerio_report["Recommended Actions"] = cynerio_report.apply(create_recommendedactions, axis=1)
cynerio_report["Alert URL"] = cynerio_report.apply(create_alertURL, axis=1)
cynerio_report["OS Version"] = cynerio_report.apply(create_os_version, axis=1)
cynerio_report["Alert Description"] = cynerio_report.apply(create_alert_description, axis=1)

# Delete rows with empty cell in CVE & Model column
cynerio_report.dropna(subset=["CVE & Model"], inplace=True)

# De-duplicate df based on the CVE & Model column
cynerio_report = cynerio_report.drop_duplicates(subset=["CVE & Model"])

# create model assignment dictionary (TODO include input about how many tickets each analyst has before the rest of the script is run, that way it can put the analyst with the least amount of tickets in the first spot and so on)
# this should be a separate csv that can be referenced for the other scripts that need a list of analysts, that way I only need to update one list for all scripts
analysts = ["Zarrar Ahmed", "Yasir Zubair", "Muhammad Usman", "Bazil Arif", "Dawood Shaikh", "Saad Sheikh", "Zain Abdeen", "Mubashir Hussain", "Uzair Khan"]

# pull all device models into a list
raw_models = cynerio_report["Model"].tolist()

# sort model list by frequency of occurence
sorted_models = [item for items, c in Counter(raw_models).most_common()
                 for item in [items] * c]

# remove duplicates in model list, but keep the placement of the list items
final_model_list = []
for item in sorted_models:
    if item == "":
        continue
    if item not in final_model_list:
        final_model_list.append(item)

# the following 9 lines pair up the models with the analysts, reverses the analyst list and loops through it if the model list is longer
# not a perfect solution to ticket distribution and requires changing the order of the analysts based on existing tickets or additions to the team
model_assignments = {}
analyst = 0

for key in final_model_list:
    model_assignments[key] = analysts[analyst]
    analyst = analyst + 1
    if analyst == len(analysts):
        analysts.reverse()
        analyst = 0

cynerio_report["Current Owner"] = cynerio_report.apply(current_owner, axis=1)

cynerio_report.rename(columns= {'Asset ID':'IoT Tool Identified Asset/Device ID'}, inplace = True)
cynerio_report.rename(columns= {'Name':'Risk / CVE Name'}, inplace = True)
cynerio_report.rename(columns= {'Vendor':'Make'}, inplace = True)

# creates an output csv
output_csv = cynerio_report[["Risk Instance ID", "IoT Tool Identified Asset/Device ID", "Alert URL", "Summary", "Risk / CVE Name", "Make", "Model", "OS Version", "MAC", "IP Address", "Issue Type", "Priority", "Severity", "Alert Description", "Recommended Actions", "Current Owner"]]
timestamp = datetime.now().strftime("%Y_%m_%d-%I.%M.%S %p")
output_csv.to_csv(f"formatted_cynerio_vulns - {timestamp}.csv", sep=",", index=False, encoding="utf-8")

input("Success! Press Enter to exit...")
