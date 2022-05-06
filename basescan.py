import shodan
import fileinput
import config

#FUNCTION to search shodan for the Campus IPs and ports and return each campus to a <campus>_base.txt file
def shodan_query(ip, name):
        try:
                # Search Shodan for campus
                results = api.search('net:'+ip)

                # open file
                file1 = open(name + "_base.txt", "w")
                #loop through the search results and pull out IP and Port and putting it in the list, result_list
                result_list = []
                for result in results['matches']:
                        #add IP and Port to result_list
                        result_list.append(str(result['ip_str']) + ":" + str(result['port']) + "\n")
                #sort the list
                #not base sort, 113 > 7
                result_list.sort()
                
                #iterate through result_list and write to file
                for items in result_list:
                        file1.writelines(items)
                file1.close()
        #catch any errors that shodan throws and report to console
        #probably add this to a teams message at some point
        except shodan.APIError as e:
                print('Error: {}'.format(e))



#MAIN

#VARIABLES
# add API key
SHODAN_API_KEY = config.SHODAN_API_KEY
api = shodan.Shodan(SHODAN_API_KEY)
#declare and initialize campus IP range variable
ip = ""
#declare and initialize campus name variable
name = ""
print(config.load_screen)

#get the campus CIDR blocks from campuses.cfg file
with fileinput.FileInput(files=('campus.cfg'), mode='r') as input:
    for line in input:
        #print(line)
        #if the first character of the line is a digit it gets sent to the IP variable    
        if line.startswith(('0','1','2','3', '4', '5', '6', '7', '8', '9')):
             ip = line.strip()
        #if the first character is anything else its value gets sent to name
        else:
            #need to strip /n off
            name = line.strip()
            #we have a name line, so wipe value in ip
            ip = ""
        #prevent anything but a number (IP) from doing a search
        if ip != "":
            shodan_query(ip, name)
            print(name + " " + ip + " is complete.")
