import shodan
import fileinput
import config

#FUNCTIONS

#FUNCTION to search for Campus info and return IP and port to a new_campus.txt file
def shodan_query(ip, name):
        try:
                # Search Shodan for campus
                results = api.search('net:'+ip)

                # open file
                
                file1 = open(name + "_base.txt", "w")
                #loop through the search results and pull out IP and Port and putting it in a list, result_list
                result_list = []
                for result in results['matches']:
                        #add IP and Port to list
                        result_list.append(str(result['ip_str']) + ":" + str(result['port']) + "\n")

                #sort the list
                result_list.sort()
                
                #go through the list and write to file
                for items in result_list:
                        file1.writelines(items)
                file1.close()

        except shodan.APIError as e:
                print('Error: {}'.format(e))

def load_screen():
        print("""\


░██████╗██╗░░░██╗███╗░░██╗██╗░░░██╗  ░██████╗░█████╗░░█████╗░
██╔════╝██║░░░██║████╗░██║╚██╗░██╔╝  ██╔════╝██╔══██╗██╔══██╗
╚█████╗░██║░░░██║██╔██╗██║░╚████╔╝░  ╚█████╗░██║░░██║██║░░╚═╝
░╚═══██╗██║░░░██║██║╚████║░░╚██╔╝░░  ░╚═══██╗██║░░██║██║░░██╗
██████╔╝╚██████╔╝██║░╚███║░░░██║░░░  ██████╔╝╚█████╔╝╚█████╔╝
╚═════╝░░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░  ╚═════╝░░╚════╝░░╚════╝░

██████╗░░█████╗░░██████╗███████╗  ░██████╗░█████╗░░█████╗░███╗░░██╗██╗░░██╗░░
██╔══██╗██╔══██╗██╔════╝██╔════╝  ██╔════╝██╔══██╗██╔══██╗████╗░██║╚██╗░╚██╗░
██████╦╝███████║╚█████╗░█████╗░░  ╚█████╗░██║░░╚═╝███████║██╔██╗██║░╚██╗░╚██╗
██╔══██╗██╔══██║░╚═══██╗██╔══╝░░  ░╚═══██╗██║░░██╗██╔══██║██║╚████║░██╔╝░██╔╝
██████╦╝██║░░██║██████╔╝███████╗  ██████╔╝╚█████╔╝██║░░██║██║░╚███║██╔╝░██╔╝░
╚═════╝░╚═╝░░╚═╝╚═════╝░╚══════╝  ╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝░░



                    """)


#VARIABLES

# add API key
SHODAN_API_KEY = config.SHODAN_API_KEY
api = shodan.Shodan(SHODAN_API_KEY)

#set campus range to nothing
ip = ""
#set campus name to nothing
name = ""
load_screen()


#get the campus CIDR blocks from campuses.txt file
with fileinput.FileInput(files=('campus.cfg'), mode='r') as input:
    for line in input:
        #print(line)
        #if the first character of the line is a digit it gets sent to the IP variable    
        if line.startswith(('0','1','2','3', '4', '5', '6', '7', '8', '9')):
             ip = line.strip()
             
        #if the first character is anything else its value gets sent to name
        else:  
            name = line.strip()
            #we have hit the name line, erase value in ip
            ip = ""
        #prevent anything but a numer (IP) from doing an search
        if ip != "":
            shodan_query(ip, name)
            print(name + " " + ip + " is complete.")
