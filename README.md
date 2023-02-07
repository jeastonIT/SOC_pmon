# SOC_pmon


The goal of this project is to monitor all campus externally visible network IPs and Ports and to notify the campus when a new asset appears externally. 
This scope has been narrowed to only notify regarding ports of concern on a monthly basis. (As 30 days is the expiration date of assets in Shodan's database) 
Additionally, the scope has been expanded to return shodan verified vulnerabilities. 

basescan.py

This program is depreciated. This program will query shodan for all campus IPs and Ports showing for their CIDR block ranges and save these as a <campus>_base.txt file.
However, we now use the _base.txt as an allow list. So it is blank except for assets which are not to be included in notifications. 
  
pmon.py 
  
This program will query shodan for a new set externally visible campus IPs and Ports and compare this result to the campus base scans, which act as an allow list. 
There are 3 functions
shodan_query, which does the query and saves results to _new.txt file. 
vuln_query, which searches for verified vulns in the campus range and saves results to a timestamped results folder


Additionally, the results are sorted by ports of concern and 


allow.py

This program will allow a user to add an IP address and a port to the base scan file.   

campus.cfg
  
Campus IP data is kept in the campus.cfg file. The format is Campus Name, then on the next line CIDR blocks seperated by a comma. No blank lines. 

config.py
  
the config.py keeps the API keys for shodan API and msteams API. 

---------------------------------------------------

### INSTALL 

You will probably need pip and the Shodan Library

apt install python3-pip

pip install shodan

pip install pymsteams

copy basescan.py, config.py, campus.cfg, pmon.py to a folder.


### CONFIGURE 

In campus.cfg, put the Campus name on a line and on the line below it have the campus CIDR blocks seperated by a comma. Then the next campus name with no blank lines between.

For example:

Campus A
1.1.1.1/8,2.2.2.2/12
Campus B
3.3.3.3/24

**no empty lines**

### RUN FIRST TIME EVER - Get base scans

Put all files are in one folder. 
run basescan.py to create a fresh base for campuses networks


### PERIMETER MONITOR!

run pmon.py to get a "latest scan" which will compare against base files.
results will be sent to teams and a local file created. 

Example
Results_2022_05_06_12_18.txt

### Remove PORT from being detected as "exposed" 
So if a campus is ok with a port, manually add it to their base file.

### About Perimeter Monitor VM
files are in /usr/bin/pmon
cron job runs every day at 5 am

