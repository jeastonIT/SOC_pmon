import shodan
import fileinput
import config

#FUNCTION to search shodan for the Campus IPs and ports and return each campus to a <campus>_base.txt file
def shodan_query(ip, name):
        try:
                print("SOC Perimeter Monitoring is scanning " + name + "...")
                # Search Shodan for campus

                result_list = []
                page = 0
                while len(result_list) >= (page * 90):
                    page = page + 1
                    results = api.search('net:' + ip, page, minify=True)
                    # loop through the search results and pull out IP and Port and putting it in a list, result_list
                    for result in results['matches']:
                        # add IP and Port to list
                        result_list.append(str(result['ip_str']) + ":" + str(result['port']) + "\n")
                    print(len(result_list))
                #not base sort, 113 > 7
                result_list.sort()
                # create a file to store new result
                file1 = open(name + "_base.txt", "w")
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

# get the campus CIDR blocks from campus.cfg file
with fileinput.FileInput(files=('campus.cfg'), mode='r') as input:
    for line in input:
        # print(line)
        # if the first character of the line is a digit it gets sent to the IP variable
        if line.startswith(('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')):
            ip = (line)
            shodan_query(ip, name)
        # if the first character is anything else its value gets sent to name
        else:
            name = line.strip()