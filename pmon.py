import shodan
from datetime import datetime
import difflib
from difflib import Differ
import fileinput
#import pymsteams
import config
import os

#FUNCTIONS

# search for Campus info and return IP and port to a new_campus.txt file and then diff the two results
def shodan_query(ip, name):
        try:
                print("SOC Perimeter Monitoring is scanning " + name + "...")
                # Search Shodan for campus

                result_list = []
                page = 0
                #need to read multiple pages of the shodan search, "about" 100 results per page.
                while len(result_list) >= (page*90):
                    page = page + 1
                    #results is a dictionary
                    results = api.search('net:'+ip+' -hash:0',page,minify=True)
                    # loop through the search results and pull out IP and Port and putting it in a list, result_list
                    for result in results['matches']:
                        # add IP and Port to list
                        result_list.append(str(result['ip_str']) + ":" + str(result['port']) + "\n")
                    print(len(result_list))



                # sort the list
                result_list.sort()

                #create a file to store new result
                file1 = open (name + "_new.txt", "w")
                #go through the list and write to file
                for items in result_list:
                        file1.writelines(items)
                file1.close()


        except shodan.APIError as e:
                print('Error: {}'.format(e))

#search the campus CIDR block for vulns and write any to a _vulns.txt file in timestamped results folder.
def vuln_query(ip, name, path):
    try:

        print("Querying Shodan database for " + " any vuln on " + name + " external network" + "...")
        # Search Shodan for campus
        result_list = []
        # ADD VULN HERE
        # vuln = 'CVE-2022-41040'
        FACETS = [
            'vuln.verified',
        ]
        # remove new line from string
        ip = ip.strip()
        # QUERY for vuln
        query = 'net:' + ip  # + ' vuln:' + vuln
        # query for exchange servers + vuln
        # query = 'net:' + ip + ' http.title:outlook exchange ' + 'vuln:' + vuln
        vuln_results = api.count(query, facets=FACETS)

        vuln_results_list = vuln_results['facets']['vuln.verified']
        if vuln_results_list:
            for i in range(len(vuln_results_list)):
                vuln_result = vuln_results_list[i]
                vuln = vuln_result['value']
                query = 'net:' + ip + ' vuln:' + vuln
                results = api.search(query, minify=True)
                # loop through the search results and pull out IP and Port and putting it in a list, result_list
                for result in results['matches']:
                    # add IP and Port to list
                    result_list.append(str(result['ip_str']) + ":" + str(result['port']) + " " + vuln + "\n")

        # create a file to store new result
        # file name for exchange server
        # file1 = open(name + "_exchange_vuln.txt", "w")
        # file name for vuln search
        # iterate through result_list and write to file
        result = ""
        for items in result_list:
            result = result + items
        #check if there is any result
        if result:
        # file name for vuln search
                file1 = open(path + "/" + name + "_vulns.txt", "w")
                file1.writelines(result)
                file1.close()
        else:
            print('no result')
        print(result)
    except shodan.APIError as e:
        print('Error: {}'.format(e))

#compares the base and new scan files and filters for ports of concern AND writes to a result folder
def differ(name, path):

                change=""
                with open(name + '_base.txt') as file_1, open(name + '_new.txt') as file_2:
                    differ = Differ()
                    for line in differ.compare(file_1.readlines(), file_2.readlines()):
                        #decide whether or not to show the asset (line)
                        line_show = False
                        #we are looking for these ports
                        ports_of_concern = [21 ,22 ,23 ,25 ,53 ,69 ,88 ,135 ,137 ,139 ,161 ,179 ,
                                            445 ,464 ,512 ,513 ,514 ,1433 ,1434 ,2049 ,2100 ,2483 ,
                                            2484 ,3290 ,3306 ,3389 ,4333 ,5432 ,9100 ,27019
                        ]
                        for i in ports_of_concern:
                        #checking for all the ports of concerns, setting line_show true if found
                            if line.endswith(":" + str(i) + '\n'):
                                line_show = True
                        #only output new visible assets that match the ports of concern
                        if line.startswith('+') and line_show:
                                #print(line)
                                #change = change + "| " + line
                                change = change + line
                #output change to the screen
                print(change)
                #setup the new folder
                if change != "":
                    file1 = open(path + "/" + name + "_Results_.txt", "w")
                    file1.write(change)
                    file1.close



#full unified diff for the file output
def unified_diff(name):

        #variables
        base_scan = name + "_base.txt"
        new_scan = name + "_new.txt"
        result=""
        #unified_diff
        with open(base_scan) as file_1:
            file_1_text = file_1.readlines()

        with open(new_scan) as file_2:
            file_2_text = file_2.readlines()

        # Find and print the unified diff:
        for line in difflib.unified_diff(file_1_text, file_2_text, fromfile=base_scan, tofile=new_scan, lineterm=''):
            #print(line)
            result = result + line + "\n"
        return result



#MAIN

#Pull in API Keys from config.py file
SHODAN_API_KEY = config.SHODAN_API_KEY
api = shodan.Shodan(SHODAN_API_KEY)

#MSTEAMS_API_KEY = config.MSTEAMS_API_KEY
#myTeamsMessage = pymsteams.connectorcard(MSTEAMS_API_KEY)

#initialize variable
#campus ip
ip = ""
#campus name
name = ""
#result for teams
#campus_result = ""
#result for file
comp_result = ""

#variable used for file name
time = datetime.now().strftime("%Y_%m_%d_%H_%M")

#run fun screen
print(config.load_screen)

#make results folder time stamped
directory = 'results_' + time
parent_dir = config.parent_dir
path = os.path.join(parent_dir,directory)
os.mkdir(path)


#get the campus CIDR blocks from campus.cfg file
#change campus.cfg to test_campus.cfg to work on
with fileinput.FileInput(files=('campus.cfg'), mode='r') as input:
    for line in input:
        #print(line)
        #if the first character of the line is a digit it gets sent to the IP variable
        if line.startswith(('0','1','2','3', '4', '5', '6', '7', '8', '9')):
             ip = (line)
             #query shodan data base for visible assets
             #not assets expire after 30days from last seen
             shodan_query(ip,name)
             vuln_query(ip,name,path)
             #comp_result is all campus results as unified diff of new and base files
             #make comp_result file output BEFORE campus_result teams output, so it has unfiltered results
             comp_result = comp_result + "\n" + unified_diff(name)
             #single campus result in result, simple diff and ports of concern filter
             # saved to results folder campus named text files
             result = differ(name, path)

             #old MSteams reporting line
             #if result != "None":
                 #myTeamsMessage.title(name)
              #   myTeamsMessage.text(result)
              #   myTeamsMessage.send()

        #if the first character is anything else its value gets sent to name
        else:
            name = line.strip()


#put all results in a time stamped file.
#time = datetime.now().strftime("%Y_%m_%d_%H_%M")
file2 = open("0_All_Results_" + time + ".txt", "w")
#send unitified diff to file
file2.write(comp_result)
file2.close