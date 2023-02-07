import shodan
import fileinput
import config
import difflib
from difflib import Differ
import pymsteams


#FUNCTION to search shodan for the Campus IPs and ports and return each campus to a <campus>_base.txt file
def shodan_query(ip, name):
        try:

                #print("Querying Shodan database for " + name + " at " + ip + "...")
                # Search Shodan for campus
########################
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
#################
#readable diff for the Teams output
def differ(name):

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
                        #print(line)
                        if line.startswith('+') and line_show:
                                #print(line)
                                #change = change + "| " + line
                                change = change + "\n" + line



#                print(change)
                #print(change)
                if change == "":
                    #return ("**" + name + "**" + ": No change " + "\n")
                    return ("None")
                else:
                    return ("**" + name + "**" + "\n" + change + "\n")


#MAIN

#VARIABLES
# add API key
SHODAN_API_KEY = config.SHODAN_API_KEY
api = shodan.Shodan(SHODAN_API_KEY)
MSTEAMS_API_KEY = config.MSTEAMS_API_KEY
myTeamsMessage = pymsteams.connectorcard(MSTEAMS_API_KEY)

#declare and initialize campus IP range variable
name = input('Enter campus name (as it appears in campus.cfg file): ')
ip = input ('Input campus CIDR ranges (comma separated, no spaces): ')
#declare and initialize campus name variable
#name = ""
#print(config.load_screen)
#ask user for CVE
#vuln = input('Enter CVE name: ')

# get the campus CIDR blocks from campus.cfg file
#with fileinput.FileInput(files=('campus.cfg'), mode='r') as campus_input:
    #for line in campus_input:
        # print(line)
        # if the first character of the line is a digit it gets sent to the IP variable
        #if line.startswith(('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')):
            #ip = (line)
shodan_query(ip, name)
#shodan_query(ip,name)
            #make comp_result file output BEFORE campus_result teams output, so it has unfiltered results
            #filter the ignore ports from the _new file
            #filter(name)
            #single campus result in result, simple diff that is reported to teams
result = differ(name)
print(result)
#myTeamsMessage.title(name)
myTeamsMessage.text(result)
myTeamsMessage.send()