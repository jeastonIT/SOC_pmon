import shodan
from datetime import datetime
import difflib
from difflib import Differ
import fileinput
#import pymsteams
import config


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

def differ(name):

                change=name
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
                                change = change + "\n" + line

                print(change)
                #put the results in a time stamped file.
                #time = datetime.now().strftime("%Y_%m_%d")
                if change != name:
                    file1 = open('/opt/pmon/results/'+ name + "_Results_.txt", "w")
                #for items in result:
                #file.writelines(items)
                    file1.write(change)
#send unitified diff to file
#file.write(comp_result)
                    file1.close

                #print(change)
                if change == "":
                #    return ("**" + name + "**" + ": No change " + "\n")
                    return ("None")
                else:
                    return (change + "\n")


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
campus_result = ""
#result for file
comp_result = ""

#run fun screen
print(config.load_screen)

#put the results in a time stamped file.
#create and open the file
time = datetime.now().strftime("%Y_%m_%d_%H_%M")
file = open("Simplified_Results_" + time + ".txt", "w")


#get the campus CIDR blocks from campus.cfg file
#change campus.cfg to test_campus.cfg to work on
with fileinput.FileInput(files=('campus.cfg'), mode='r') as input:
    for line in input:
        #print(line)
        #if the first character of the line is a digit it gets sent to the IP variable
        if line.startswith(('0','1','2','3', '4', '5', '6', '7', '8', '9')):
             ip = (line)
             shodan_query(ip,name)
             #make comp_result file output BEFORE campus_result teams output, so it has unfiltered results
             comp_result = comp_result + "\n" + unified_diff(name)
             #single campus result in result, simple diff that is reported to teams
             result = differ(name)
             #campus result gets each new campus result added
             #campus_result = campus_result + "\n" + result
             #have each campus reported to Teams (instead of entire campus result
             #if result != "None":
                 #myTeamsMessage.title(name)
              #   myTeamsMessage.text(result)
              #   myTeamsMessage.send()

             #put the results into the simplied file
             for items in result:
                 file.writelines(items)
        #if the first character is anything else its value gets sent to name
        else:
            name = line.strip()


#put the results in a time stamped file.
time = datetime.now().strftime("%Y_%m_%d_%H_%M")
file2 = open("0_All_Results_" + time + ".txt", "w")
#send unitified diff to file
file.write(comp_result)
file.close

