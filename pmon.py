import shodan
from datetime import datetime
import difflib
from difflib import Differ
import fileinput
import pymsteams
import config


#FUNCTIONS

# search for Campus info and return IP and port to a new_campus.txt file and then diff the two results

def shodan_query_diff(ip, name):
        try:
                print("SOC Perimeter Monitoring is scanning " + name + "...")
                # Search Shodan for campus
                results = api.search('net:'+ip)

                #create a file to store new result
                file1 = open (name + "_new.txt", "w")
                result_list = []
                #loop through the search results and pull out IP and Port and putting it in a list, result_list
                for result in results['matches']:
                        #add IP and Port to list
                        result_list.append(str(result['ip_str']) + ":" + str(result['port']) + "\n")

                #sort the list
                result_list.sort()
                
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
#def differ(name):
                #DIFF a more readable diff

                """change=""
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
"""

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


#load screen function
                
def load_screen():
        print("""\


░██████╗██╗░░░██╗███╗░░██╗██╗░░░██╗  ░██████╗░█████╗░░█████╗░  
██╔════╝██║░░░██║████╗░██║╚██╗░██╔╝  ██╔════╝██╔══██╗██╔══██╗  
╚█████╗░██║░░░██║██╔██╗██║░╚████╔╝░  ╚█████╗░██║░░██║██║░░╚═╝  
░╚═══██╗██║░░░██║██║╚████║░░╚██╔╝░░  ░╚═══██╗██║░░██║██║░░██╗  
██████╔╝╚██████╔╝██║░╚███║░░░██║░░░  ██████╔╝╚█████╔╝╚█████╔╝  
╚═════╝░░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░  ╚═════╝░░╚════╝░░╚════╝░  

██████╗░███████╗██████╗░██╗███╗░░░███╗███████╗████████╗███████╗██████╗░
██╔══██╗██╔════╝██╔══██╗██║████╗░████║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝█████╗░░██████╔╝██║██╔████╔██║█████╗░░░░░██║░░░█████╗░░██████╔╝
██╔═══╝░██╔══╝░░██╔══██╗██║██║╚██╔╝██║██╔══╝░░░░░██║░░░██╔══╝░░██╔══██╗
██║░░░░░███████╗██║░░██║██║██║░╚═╝░██║███████╗░░░██║░░░███████╗██║░░██║
╚═╝░░░░░╚══════╝╚═╝░░╚═╝╚═╝╚═╝░░░░░╚═╝╚══════╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝

███╗░░░███╗░█████╗░███╗░░██╗██╗████████╗░█████╗░██████╗░██╗███╗░░██╗░██████╗░
████╗░████║██╔══██╗████╗░██║██║╚══██╔══╝██╔══██╗██╔══██╗██║████╗░██║██╔════╝░
██╔████╔██║██║░░██║██╔██╗██║██║░░░██║░░░██║░░██║██████╔╝██║██╔██╗██║██║░░██╗░
██║╚██╔╝██║██║░░██║██║╚████║██║░░░██║░░░██║░░██║██╔══██╗██║██║╚████║██║░░╚██╗
██║░╚═╝░██║╚█████╔╝██║░╚███║██║░░░██║░░░╚█████╔╝██║░░██║██║██║░╚███║╚██████╔╝
╚═╝░░░░░╚═╝░╚════╝░╚═╝░░╚══╝╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═╝╚═╝░░╚══╝░╚═════╝░




                    """)


#VARIABLES

#Shodan API key
#SHODAN_API_KEY = 'wZJ7prinv4FWzr36XzsNFJPAO6WqUxZ4'

SHODAN_API_KEY = config.SHODAN_API_KEY
api = shodan.Shodan(SHODAN_API_KEY)

#msteams webhook api
#myTeamsMessage = pymsteams.connectorcard("https://sunysysadmin.webhook.office.com/webhookb2/80741552-0f13-46fb-8f27-54f9ac0ef689@313006a2-ae5d-4419-9e34-8f765b197fb8/IncomingWebhook/03feee30270d42349aeff2519cf7ab2d/0e323094-f8ee-4e37-8f31-9b4348a3efa9")
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
load_screen()

#get the campus CIDR blocks from campus.cfg file
with fileinput.FileInput(files=('campus.cfg'), mode='r') as input:
    for line in input:
        #print(line)
        #if the first character of the line is a digit it gets sent to the IP variable    
        if line.startswith(('0','1','2','3', '4', '5', '6', '7', '8', '9')):
             ip = (line)
             
        #if the first character is anything else its value gets sent to name
        else: 
            name = line.strip()
            #we have hit the name line, erase value in ip
            ip = ""
        #prevent anything but a number (IP) from doing an search
        if ip != "":
            #probably can move this to first If statement
            campus_result = campus_result + "\n" + shodan_query_diff(ip, name)
            comp_result = comp_result + "\n" + unified_diff(name)

#put the results in a time stamped file.
time = datetime.now().strftime("%Y_%m_%d_%H_%M")
file = open("Results_" + time + ".txt", "w")
file.write(comp_result)
file.close

#send a message to the Perimonitor Teams channel
myTeamsMessage.title("SOC Perimeter Monitoring Report")
myTeamsMessage.text(campus_result)
myTeamsMessage.send()

"""

 (              )      )   (        )                         
 )\ )        ( /(   ( /(   )\ )  ( /(    (                    
(()/(    (   )\())  )\()) (()/(  )\())   )\                   
 /(_))   )\ ((_)\  ((_)\   /(_))((_)\  (((_)                  
(_))  _ ((_) _((_)__ ((_) (_))    ((_) )\___                  
/ __|| | | || \| |\ \ / / / __|  / _ \((/ __|                 
\__ \| |_| || .` | \ V /  \__ \ | (_) || (__                  
|(__/ \___/ |_|\_|  |_|   |___/  \___/  \___|                 
______         _                _                   
| ___ \       (_)              | |                  
| |_/ /__ _ __ _ _ __ ___   ___| |_ ___ _ __        
|  __/ _ \ '__| | '_ ` _ \ / _ \ __/ _ \ '__|       
| | |  __/ |  | | | | | | |  __/ ||  __/ |          
\_|  \___|_|  |_|_| |_| |_|\___|\__\___|_|          
                                                    
                                                    
___  ___            _ _             _             _ 
|  \/  |           (_) |           (_)           | |
| .  . | ___  _ __  _| |_ ___  _ __ _ _ __   __ _| |
| |\/| |/ _ \| '_ \| | __/ _ \| '__| | '_ \ / _` | |
| |  | | (_) | | | | | || (_) | |  | | | | | (_| |_|
\_|  |_/\___/|_| |_|_|\__\___/|_|  |_|_| |_|\__, (_)
                                             __/ |  
                                            |___/   


               """



##OLD JUNK
            
#find the difference between the old file and the new.

"""
with open('old_campus.txt') as file_1:
    file_1_text = file_1.readlines()

with open('new_campus.txt') as file_2:
    file_2_text = file_2.readlines()

# Find and print the unified diff:
for line in difflib.unified_diff(
       file_1_text, file_2_text, fromfile='old_campus.txt', tofile='new_campus.txt', lineterm=''):
    print(line)
"""



