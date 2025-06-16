import os
import pandas as pd
from collections import Counter

# Changes the cwd to the directory of the file
current_directory = os.path.dirname(__file__)
os.chdir(current_directory)

# Remove existing formatted_asimily_vulns.csv from the folder location
if os.path.isfile("./formatted_asimily_vulns.csv"):
    os.remove(current_directory + "\\formatted_asimily_vulns.csv")

# convert the xlsx asimily report into csv
xlsx_report = pd.read_excel("asimily_vulns.xlsx").copy() #.fillna("")
xlsx_report.to_csv("asimily_vulns.csv")
vuln_report = pd.read_csv("asimily_vulns.csv", keep_default_na=False)

def current_owner(row):
    return model_assignments[row["Device Model"]]

def create_trackingID(row):
    return f"{row["CVE ID"]}-{str(row["Device ID"])}"

# create_cve_model function combines the two fields and allows the df to be de-duped, used to only create one ticket per cve and model
def create_cve_model(row):
    if not row["Device Model"]:
        return
    else:
        return f"{row["CVE ID"]}-{str(row["Device Model"])}"

def create_summary(row):
    return f"Asimily flagged this device as vulnerable to {str(row["CVE ID"])}. " + row["CVE Description"]

def create_severity(row):
    return row["Criticality"].lower().capitalize()

def create_issuetype(row):
    return "Vulnerability"

# old alert url to CVE entry in NVD
# def create_alertURL(row):
#     return f"https://nvd.nist.gov/vuln/detail/{str(row["CVE ID"])}"

def create_alertURL(row):
    return f"https://uchealth-portal.asimily.com/index.html#/asset/1/{str(row["Device ID"])}/likelihood"

def create_recommendedactions(row):
    return """Investigate the impact of the CVE on the model. Find the answers for these questions:
        - Is the model vulnerable to the CVE? 
        - If so, is there a validated patch (or compensating control) that can be applied?
        
Follow the vulnerability management workflow after gathering the answers."""

# Severity is based on Asimily's CVSS 3 Base Score, but aligned to NVD's qualitative severity ratings for CVSS v4.0
#  Asimily CVE Score bands
#    High: >= 8
#    Medium: < 8 && >=4
#    Low: < 4 && >= 1
#  CVSS v4.0 Qualitative Severity Ratings
#    Low:        0.1 - 3.9
#    Medium:     4.0 - 6.9
#    High:       7.0 - 8.9
#    Critical:   9.0 - 10.0

def create_severity(row):
    if row["CVSS 3 Base Score"] >= 9.0:
        return "Critical"
    elif row["CVSS 3 Base Score"] <= 8.9 and row["CVSS 3 Base Score"] >=7.0:
        return "High"
    elif row["CVSS 3 Base Score"] <= 6.9 and row["CVSS 3 Base Score"] >=4.0:
        return "Medium"
    elif row["CVSS 3 Base Score"] <= 3.9 and row["CVSS 3 Base Score"] >=.1:
        return "Low"
    
def create_priority(row):
    if row["CVSS 3 Base Score"] >= 9.0 and row["CVE Score"] >= 9.0:
        return "1-Immediate"
    elif row["CVE Score"] >= 9.0:
        return "2-Critical"
    elif row["CVE Score"] <= 8.9 and row["CVE Score"] >=7.0:
        return "3-Important"
    elif row["CVE Score"] <= 6.9 and row["CVE Score"] >=4.0:
        return "4-Standard"
    else:
        return "5-Low"

vuln_report["Issue Type"] = vuln_report.apply(create_issuetype, axis=1)
vuln_report["Severity"] = vuln_report.apply(create_severity, axis=1)
vuln_report["Priority"] = vuln_report.apply(create_priority, axis=1)
vuln_report["Summary"] = vuln_report.apply(create_summary, axis=1)
vuln_report["Tracking ID"] = vuln_report.apply(create_trackingID, axis=1)
vuln_report["CVE & Model"] = vuln_report.apply(create_cve_model, axis=1)
vuln_report["Recommended Actions"] = vuln_report.apply(create_recommendedactions, axis=1)
vuln_report["Alert URL"] = vuln_report.apply(create_alertURL, axis=1)

# Delete rows with empty cell in CVE & Model column
vuln_report.dropna(subset=["CVE & Model"], inplace=True)

# De-duplicate df based on the CVE & Model column
vuln_report = vuln_report.drop_duplicates(subset=["CVE & Model"])

# create model assignment dictionary (TODO include input about how many tickets each analyst has before the rest of the script is run)
analysts = ["Dawood Shaikh", "Muhammad Usman", "Bazil Arif", "Saad Sheikh", "Zain Abdeen", "Mubashir Hussain", "Uzair Khan"]

# pull all device models into a list
raw_models = vuln_report["Device Model"].tolist()

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

# lines 113 through 121 pair up the models with the analysts, reverses the analyst list and loops through it if the model list is longer
# not a perfect solution to ticket distribution and requires changing the order of the analysts based on existing tickets or additions to the team
model_assignments = {}
analyst = 0

for key in final_model_list:
    model_assignments[key] = analysts[analyst]
    analyst = analyst + 1
    if analyst == len(analysts):
        analysts.reverse()
        analyst = 0

vuln_report["Current Owner"] = vuln_report.apply(current_owner, axis=1)
vuln_report.rename(columns= {'Device ID':'IoT Tool Identified Asset/Device ID'}, inplace = True)
vuln_report.rename(columns= {'CVE Description':'Alert Description'}, inplace = True)

# creates a final csv
vuln_report.to_csv("formatted_asimily_vulns.csv", sep=",", index=False, encoding="utf-8")

# removes the converted csv from xlsx report
os.remove(current_directory + "\\asimily_vulns.csv")

input("Success! Press Enter to exit...")
