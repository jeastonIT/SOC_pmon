import shodan
from datetime import datetime
import difflib
from difflib import Differ
import fileinput
import pymsteams
import config


#FUNCTIONS

# search for Campus info and return IP and port to a new_campus.txt file and then diff the two results
def shodan_query(ip, name):
        try:
                print("SOC Perimeter Monitoring is scanning " + name + "...")
                # Search Shodan for campus


                result_list = []
                page = 0
                while len(result_list) >= (page*100)-4:
                    page = page + 1
                    results = api.search('net:'+ip,page,minify=True)
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

                #DIFF a more readable diff
                change=""
                with open(name + '_base.txt') as file_1, open(name + '_new.txt') as file_2:
                    differ = Differ()
                    for line in differ.compare(file_1.readlines(), file_2.readlines()):
                        #only output changes instead of what stayed the same
                        #if line.startswith(('+','-')):
                        if line.startswith(('+')):
                                #print(line)
                                #change = change + "| " + line
                                change = change + "\n" + line

                print(change)
                if change == "":
                    return ("**" + name + "**" + ": No change " + "\n")
                else:
                    return ("**" + name + "**" + "\n" + change + "\n")


        except shodan.APIError as e:
                print('Error: {}'.format(e))

#readable diff for the Teams output
def differ(name):

                change=""
                with open(name + '_base.txt') as file_1, open(name + '_new.txt') as file_2:
                    differ = Differ()
                    for line in differ.compare(file_1.readlines(), file_2.readlines()):
                        #only output changes instead of what stayed the same
                        #if line.startswith(('+','-')):
                        if line.startswith(('+')):
                                #print(line)
                                #change = change + "| " + line
                                change = change + "\n" + line

                print(change)
                if change == "":
                    return ("**" + name + "**" + ": No change " + "\n")
                else:
                    return ("**" + name + "**" + "\n" + change + "\n")

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

MSTEAMS_API_KEY = config.MSTEAMS_API_KEY
myTeamsMessage = pymsteams.connectorcard(MSTEAMS_API_KEY)

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

#get the campus CIDR blocks from campus.cfg file
with fileinput.FileInput(files=('campus.cfg'), mode='r') as input:
    for line in input:
        #print(line)
        #if the first character of the line is a digit it gets sent to the IP variable    
        if line.startswith(('0','1','2','3', '4', '5', '6', '7', '8', '9')):
             ip = (line)
             shodan_query(ip,name)
             campus_result = campus_result + "\n" + differ(name)
             comp_result = comp_result + "\n" + unified_diff(name)
             
        #if the first character is anything else its value gets sent to name
        else: 
            name = line.strip()


#put the results in a time stamped file.
time = datetime.now().strftime("%Y_%m_%d_%H_%M")
file = open("Results_" + time + ".txt", "w")
file.write(comp_result)
file.close

#send a message to the Perimonitor Teams channel
myTeamsMessage.title("SOC Perimeter Monitoring Report")
myTeamsMessage.text(campus_result)
myTeamsMessage.send()