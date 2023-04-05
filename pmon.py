import shodan
from datetime import datetime
import difflib
from difflib import Differ
import fileinput
import config
import os
import sys
import ipaddress as ip_add
import time

#Functions

#Animation function
def loading():
        print("Loading....")

        animation = ["[■□□□□□□□□□]","[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

        for i in range(len(animation)):
                time.sleep(0.5)
                sys.stdout.write("\r" + animation[i % len(animation)])
                sys.stdout.flush()
print('\n')




#This function filters out DNS records with the CIDR ranges.
#@param: IP_range-> it is a single IP range of a campus
#@param: public_IPs: list of public for a specific doiman
#@returns: It returns the IP ranges that are out of the range.
def filter_DNS_records(IP_range, public_IPs):
        #List of output with filtered IPs
        output_IP_list = []
        #Eliminating IPs those are already in the range of CIDR blocks
        for i in public_IPs:
                if(ip_add.ip_address(i) in ip_add.ip_network(IP_range)):
                        continue
                else:
                        output_IP_list.append(i)

        return output_IP_list

#This function looks for the IPs from the DNS records
#@param: domain_name-> It is the domain name of the campus.
#@param: IP_list:-> It is a list of IP ranges of a campus.
def DNS_record_query(domain_name, IP):
        time.sleep(2)
        public_IPs = ""
        try:
                print("Searching DNS records for " + domain_name + "...")
                result_list = []

                #initalize shodan database
                init_shodan = "shodan init " + SHODAN_API_KEY
                os.system(init_shodan + " >/dev/null 2>&1")

                #Command for searching DNS records
                domain_search = "shodan domain -T A -S " + domain_name
                os.system(domain_search + " >/dev/null 2>&1")

                #Filter out the DNS records from the JSON file
                parse_results = "shodan parse --fields value " + domain_name + ".json.gz > " + name + "_DNS.txt"
                os.system(parse_results)
                #removes the .json file
                remove_json = "rm " + domain_name + ".json.gz"
                os.system(remove_json)
                #Storing the public IPs and removing the private IPs out from the search results.
                domain_search_results = []
                file1 = open(name + "_DNS.txt", "r")
                lines = file1.readlines()
                file1.close()

                #removes duplicate IPs from the list
                lines = [*set(lines)]

                count = 0 #counter variable
                public_IPs = [] #list of public IP addresses in the DNS records


                #Filters out the public IP addresses from the DNS records
                for i in lines:
                        i = i.rstrip('\n')
                        if(ip_add.ip_address(i).is_private):
                                continue
                        else:
                                public_IPs.append(i)

                #Parting the IP ranges into a list.
                #Store IP ranges of one campus at a time
                temp_IP_list = []
                #temproray variable to append to the IP ranges list.
                temp_IP = ""
                #Converts the IP range string into a list
                for j in IP:
                        count += 1
                        j = j.rstrip('\n')
                        if(j == ','):
                                temp_IP_list.append(temp_IP)
                                temp_IP = ""
                                continue
                        else:
                                temp_IP += j

                #Adds the last IP range to the list if there are more than 1 IP ranges.
                if(count > 1):
                        temp_IP_list.append(temp_IP)

                counter = 0 #counter variable
                final_results = []
                #run the filter DNS records function to get the filtered results.
                for m in temp_IP_list:
                        final_results = filter_DNS_records(temp_IP_list[counter], public_IPs)
                        public_IPs = final_results
                        counter += 1


                #Removing the DNS records file
                remove = "rm " + name + "_DNS.txt"
                os.system(remove)

        except shodan.APIError as e :
                print('Error: {}'.format(e))

        return final_results



#Search for Campus info and return IP and ports to a new_campus.txt file and then diff the two results
def shodan_query(IP,name):
        time.sleep(2)
        try:
                print("Querying Shodan database for " + name +" assets: ")
                #Search Shodan for campus

                result_list = []
                page = 0
                print(IP)
                #Need to read multiple pages of the shodan search, "about" 100 results per page
                while len(result_list) >= (page*90):
                        page += 1
                        #results is a directory
                        results = api.search('net:' + IP + ' -hash:0', page, minify = True)
                        #loop through the search results and pull out IP and Port and Putting it in a list, result_list
                        for result in results ['matches']:
                                #add IP and port to list
                                result_list.append(str(result['ip_str']) + ":" + str(result['port']) + "\n")
                        loading()
                        print(len(result_list))

                #Sort the list
                result_list.sort()

                #create a file to store new result
                file1 = open (name + "_new.txt", "w")
                #go through the list and write to file
                for items in result_list:
                        file1.writelines(items)
                file1.close()
        except shodan.APIError as e:
                print("Error: {}".format(e))



def vuln_query(IP, name, path):
        time.sleep(2)
        try:


                print("Querying Shodan database for any verified vulnerablity on " + name + " external network" + "....")
                #Search Shodan for campus
                result_list = []
                #Add vuln here
                FACETS = [
                        'vuln.verified',
                ]
                #remove new line from string
                IP = IP.strip()
                #Query for vuln
                query = 'net:' + IP
                vuln_results = api.count(query, facets = FACETS)

                vuln_results_list = vuln_results['facets']['vuln.verified']
                if vuln_results_list:
                        for i in range(len(vuln_results_list)):
                                vuln_result = vuln_results_list[i]
                                vuln = vuln_result['value']
                                query = 'net:' + IP + ' vuln:' + vuln
                                results = api.search(query, minify = True)
                                #loop through the search results and pull out IP and port and putting it into a list, result_list
                                for result in results['matches']:
                                        #Add IP and Port to list
                                        result_list.append(str(result['ip_str']) + ":" + str(result['port']) + " " + vuln + "\n")

                #create a file to store new results
                # file name for vuln search
                #iterate through results_list and write to file
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
                        print("no results")
                print(result)
        except shodan.APIError as e:
                print("Error: {}".format(e))


def differ(name, path):
        time.sleep(2)
        #print('Name: '+name + ' path: '+ path)
        change = ""
        with open(name + '_base.txt') as file_1, open(name + '_new.txt') as file_2:
                differ = Differ()
                for line in differ.compare(file_1.readlines(), file_2.readlines()):
                        #decide whether or not to show the assets (line)
                        line_show = False
                        #we are loooking for these ports
                        ports_of_concern = [21,22,23,25,53,69,88,135,137,139,161,179,445,
                                                464,512,513,514,1433,1434,2049,2100,2483,
                                                2484,3290,3306,3389,4333,5432,9100,27019
                        ]
                        for i in ports_of_concern:
                        #Checking for all the ports of concern and setting line_show as true
                                if line.endswith(":" + str(i) + '\n'):
                                        line_show = True
                                        #print(line_show)
                        #Only output new visible assets that match the ports of concern
                        if  line.startswith('+') and line_show:
                                change = change + line
        #Output change to the screen
        #print("CHANGE IS!!! = " + change)
        #setup the new folder
        if change != "":
                print("*WARNING* Ports of concern found! Writing results to " + path)
                file_3 = open(path + "/" + name + "_Results_.txt", "w")
                file_3.write(change)
                file_3.close()


def unified_diff(name):

        #Variables
        base_scan = name + "_base.txt"
        new_scan = name + "_new.txt"
        result = ""
        #unified_diff
        with open(base_scan) as file_1:
                file_1_text = file_1.readlines()

        with open(new_scan) as file_2:
                file_2_text = file_2.readlines()

        #find and print the unified diff
        for line in difflib.unified_diff(file_1_text, file_2_text, fromfile = base_scan, tofile = new_scan, lineterm = ''):
                result = result + line + "\n"

        return result





#Main Function

#Pulls in API key from config.py file
SHODAN_API_KEY = config.SHODAN_API_KEY
api = shodan.Shodan(SHODAN_API_KEY)

#declare global variables
IP = ""
name = ""
domain_name = ""
comp_result = ""

#variable used for file name
time_stamp = datetime.now().strftime("%Y_%m_%d_%H_%M")

#run fun screen
print(config.load_screen)

#make results folder time stamped
directory = 'results_' + time_stamp
parent_dir = config.parent_dir
path = os.path.join(parent_dir,directory)
os.mkdir(path)

#get the campus CIDR blocks from campus.cfg file
#change campus.cfg to test_campus.cfg to work on
with fileinput.FileInput(files=('campus.cfg'), mode='r') as input:
        for line in input:
                index_val = line.find('.')
                #if the first character of the line is a digit it gets sent to the OP variable
                if line.startswith(('0','1','2','3','4','5','6','7','8','9')):
                        IP = (line)
                        counter = 0;
                        #clear DNS_IP variable for reuse
                        DNS_IPs = ""
                        #query shodan data base for visible assets
                        #not assets expire after 30 days from last seen
                        print(" ")
                        print(name)
                        #dont run for the campuses with domains run by suny.edu
                        if domain_name != "":
                                dns_results = DNS_record_query(domain_name,IP)
                                #print(dns_results)
                                #adding the DNS records IPs to the CIDR block IPs.
                                #Store the filtered DNS records list into a string.
                                for i in dns_results:
                                        DNS_IPs += i + ","
                        #Concatatinates the DNS IPs with the IPs
                        DNS_IPs = DNS_IPs.rstrip(',')
                        print("Unique public IP addresses found in DNS records: " + DNS_IPs)
                        #strips the newline character out of the IP string.
                        IP = IP.rstrip('\n')
                        IP = IP + "," + DNS_IPs
                        IP = IP.rstrip(',')
                        #Calling the Shodan Query Function
                        shodan_query(IP,name)
                        #calling differ function to get assets with ports of concern
                        differ(name, path)
                        #Calling the Vuln Query Function
                        vuln_query(IP, name, path)
                        #saved to the results folder campus name text file
                        comp_result = comp_result + "\n" + unified_diff(name)
                #Looks for the domain name in the file
                elif line[index_val] == '.':
                        domain_name = line.strip()
                        #skip the domain if it start with !, allows to ignore suny.edu shared domains
                        if line.startswith(('!')):
                                domain_name = ""
                #Looks for the Campus name in the file.
                else:
                        name = line.strip()

file2 = open("0_All_Results_" + time_stamp + ".txt", "w")

file2.write(comp_result)
file2.close()