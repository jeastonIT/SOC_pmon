# SOC_pmon


The goal of this project is to monitor all campus external network footprints and to notify then when a change occurs. 

basescan.py

This script will query shodan for all campus IPs and Ports showing for their CIDR blocks and save these as <campus>_base.txt files.
  
pmon.py 
  
This script will quest shodan for a new set of campus IP and Port information and compare it to any campus base scans. 

campus.cfg
  
Campus IP data is kept in the campus.cfg file. The format is Campus Name, then on the next line CIDR blocks seperated by a comma. No blank lines. 

config.py
  
the config.py keeps the API keys for shodan API and msteams API. 
