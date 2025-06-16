import os
import glob
import pandas as pd
from datetime import datetime
from collections import Counter

# Changes the cwd to the directory of the file
current_directory = os.path.dirname(__file__)
os.chdir(current_directory)

# this selects the necessary files to pull in without removing the characters that come with the export
for filename in os.listdir(current_directory):
    if filename.startswith("formatted_armis_vulns"):
        os.remove(filename)
    elif filename.startswith("Armis Report"):
        armis_report = pd.read_csv(filename, keep_default_na=False)
    elif filename.startswith("Related Devices"):
        related_devices = pd.read_csv(filename, keep_default_na=False)
    elif filename.startswith("model_assignments"):
        model_assignments = pd.read_csv(filename)

# have to change the column name of related devices so that I can merge with the CVE ID column of the armis report export
related_devices.rename(columns= {"Vulnerability CVE UID":"ID"}, inplace= True)

# combine the armis report and related devices csv files, causes a mess with the column names 
#   ie puts an "_x" on column names if there is a duplicate from the other csv
vuln_report = pd.merge(related_devices, armis_report, on="ID", how="inner")

def create_risk_instanceID(row):
    return f"{row["ID"]}-{str(row["Device ID"])}"

def create_issuetype(row):
    return "Vulnerability"

def current_owner(row):
    return model_assignments_dictionary[row["Model"]]

# this will have to be changed to reflect only the severity after we lose AVM in Armis
def create_priority(row):
    if row["CVSS Score v3"] >= 9.0 and row["AVM Rating_x"] == "CRITICAL":
        return "1-Immediate"
    elif row["AVM Rating_x"] == "CRITICAL":
        return "2-Critical"
    elif row["AVM Rating_x"] == "HIGH":
        return "3-Important"
    elif row["AVM Rating_x"] == "MEDIUM":
        return "4-Standard"
    else:
        return "5-Low"

def create_summary(row):
    return f"Armis flagged this device as vulnerable to {str(row["ID"])}. " + row["Description"]

def create_cve_model(row):
    if not row["Model"] or row["Model"] == "N/A":
        return
    else:
        return f"{row["ID"]}-{str(row["Model"])}"
    
def create_os_version(row):
    if row["OS"] == "N/A":
        return
    elif row["OS"] != "N/A" and row["OS Version"] == "N/A":
        return row["OS"]
    else:
        return f"{row["OS"]} {row["OS Version"]}"
    
def create_alertURL(row):
    return f"https://mercy.armis.com/inventory/devices/{str(row["Device ID"])}/risks/vulnerabilities"

def create_recommendedactions(row):
    return """Investigate the impact of the CVE on the model. Find the answers for these questions:
        - Is the model vulnerable to the CVE? 
        - If so, is there a validated patch (or compensating control) that can be applied?
        
Follow the vulnerability management workflow after gathering the answers."""

#  CVSS v4.0 Qualitative Severity Ratings
#    Low:        0.1 - 3.9
#    Medium:     4.0 - 6.9
#    High:       7.0 - 8.9
#    Critical:   9.0 - 10.0

def create_severity(row):
    if row["CVSS Score v3"] >= 9.0:
        return "Critical"
    elif row["CVSS Score v3"] <= 8.9 and row["CVSS Score v3"] >=7.0:
        return "High"
    elif row["CVSS Score v3"] <= 6.9 and row["CVSS Score v3"] >=4.0:
        return "Medium"
    elif row["CVSS Score v3"] <= 3.9 and row["CVSS Score v3"] >=.1:
        return "Low"
    
def create_alert_description(row):
    return f"{str(row["Description"])} \n\nhttps://nvd.nist.gov/vuln/detail/{str(row["ID"])}"


vuln_report["Issue Type"] = vuln_report.apply(create_issuetype, axis=1)
vuln_report["Severity"] = vuln_report.apply(create_severity, axis=1)
vuln_report["Priority"] = vuln_report.apply(create_priority, axis=1)
vuln_report["Summary"] = vuln_report.apply(create_summary, axis=1)
vuln_report["Risk Instance ID"] = vuln_report.apply(create_risk_instanceID, axis=1)
vuln_report["CVE & Model"] = vuln_report.apply(create_cve_model, axis=1)
vuln_report["Recommended Actions"] = vuln_report.apply(create_recommendedactions, axis=1)
vuln_report["Alert URL"] = vuln_report.apply(create_alertURL, axis=1)
vuln_report["OS Version"] = vuln_report.apply(create_os_version, axis=1)
vuln_report["Alert Description"] = vuln_report.apply(create_alert_description, axis=1)

# Delete rows with empty cell in CVE & Model column
vuln_report.dropna(subset=["CVE & Model"], inplace=True)

# De-duplicate df based on the CVE & Model column
vuln_report = vuln_report.drop_duplicates(subset=["CVE & Model"])

# create model assignment dictionary (TODO include input about how many tickets each analyst has before the rest of the script is run, that way it can put the analyst with the least amount of tickets in the first spot and so on)
# this should be a separate csv that can be referenced for the other scripts that need a list of analysts, that way I only need to update one list for all scripts
analysts = ["Katie Paz", "Uzair Khan", "Muhammad Usman", "Zain Abdeen", "Dawood Shaikh", "Saad Sheikh"]

# pull all device models into a list
raw_models = vuln_report["Model"].tolist()

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

# turn model_assignments into a dictionary that can be referenced
model_assignments_dictionary = model_assignments.set_index("Model")["Current Owner"].to_dict()

# identify models that are missing from the model_assignments_dictionary
unassigned_models = []
for id in sorted_models:
    if id not in model_assignments_dictionary and id not in unassigned_models:
        unassigned_models.append(id)

# the following 9 lines pair up the models with the analysts, reverses the analyst list and loops through it if the model list is longer
# not a perfect solution to ticket distribution and requires changing the order of the analysts based on existing tickets or additions to the team
new_model_assignments = {}
analyst = 0

for key in unassigned_models:
    new_model_assignments[key] = analysts[analyst]
    analyst = analyst + 1
    if analyst == len(analysts):
        analysts.reverse()
        analyst = 0

# update model_assignments_dictionary to be used in a function that populates Current Owner
model_assignments_dictionary.update(new_model_assignments)

vuln_report["Current Owner"] = vuln_report.apply(current_owner, axis=1)

vuln_report.rename(columns= {'Device ID':'IoT Tool Identified Asset/Device ID'}, inplace = True)
vuln_report.rename(columns= {'ID':'Risk / CVE Name'}, inplace = True)
vuln_report.rename(columns= {'Brand':'Make'}, inplace = True)
vuln_report.rename(columns= {'IPv4 Address':'IP'}, inplace = True)

# creates an output csv
output_csv = vuln_report[["Risk Instance ID", "IoT Tool Identified Asset/Device ID", "Summary", "Risk / CVE Name", "Make", "Model", "OS Version", "MAC", "IP", "Issue Type", "Priority", "Severity", "Alert URL", "Alert Description", "Recommended Actions", "Current Owner"]]
timestamp = datetime.now().strftime("%Y_%m_%d-%I.%M.%S %p")
output_csv.to_csv(f"formatted_armis_vulns - {timestamp}.csv", sep=",", index=False, encoding="utf-8")

# removes old model_assignments.csv to create a new one with any updates made when assigning new models
# convert updated model_assignments_dictionary into a df, rename the index, export to csv for future use
os.remove("model_assignments.csv")
updated_model_assignments = pd.DataFrame.from_dict(model_assignments_dictionary, orient="index", columns=["Current Owner"])
updated_model_assignments.index.name = "Model"
updated_model_assignments.to_csv("model_assignments.csv")

input("Success! Press Enter to exit...")
