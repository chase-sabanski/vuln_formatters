# vuln_formatters

TODO:
- script needs to parse an export of SL to determine what tickets already exist and who should get a model based on most occurrences

Workflow:
1. Pull export from ASM platform
2. Pull export from SL to determine
  a. What tickets already exist?
  b. What analyst has the most occurrences of a given model? Give them new tickets for that model.

Vuln Reqs
- Need SL export of current open tickets
    > [CVE] [Make] [Model] combined in one column to prevent duplicate tickets from being created
    > model_assignments.csv --> [Model] [Current Owner]
    
(dump from OneNote)
- High level
	○ What are the vulns that exist in Armis?
	○ What SL tickets exist for…
		§ CVE + Make + Model
		§ Models assigned to analysts
- Armis vuln upload walkthrough
	○ Pull alerts from Armis
		§ Use this ASQ line: in:vulnerabilities confidenceLevel:High,Confirmed timeFrame:"100 Days" device:(visibility:Full category:Medical) severity:Critical
		§ Exclude "IT Managed" tagged devices
	○ Save in Documents > Armis > Vuln Pulls
	○ Pull existing vuln tickets from Swimlane
		§ CVE + Make + Model --> open_sl_tickets.csv
		§ From here I can see:
			§ Open vuln tickets for BSMH
			§ Model assignments
	○ Make sure model_assignment is up to date
		§ I need a script that organizes that assigns a model to an analyst based on who has the most occurrences of that model in a ticket.
		§ Sl_assignment
Make sure analyst list is up to date
