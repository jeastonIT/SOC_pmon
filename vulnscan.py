import shodan
import fileinput
import config

#FUNCTION to search shodan for the Campus IPs and ports and return each campus to a <campus>_base.txt file
def shodan_query(ip, name):
        try:

                print("Querying Shodan database for " + " any vuln on " + name + " external network" + "...")
                # Search Shodan for campus
                result_list = []
                # ADD VULN HERE
                #vuln = 'CVE-2022-41040'
                FACETS = [
                    'vuln.verified',
                ]
                #while len(result_list) >= (page * 90):
                #page = page + 1
                    #remove new line from string
                ip = ip.strip()
                    #QUERY for vuln
                query = 'net:' + ip   #+ ' vuln:' + vuln
                    #query for exchange servers + vuln
                    #query = 'net:' + ip + ' http.title:outlook exchange ' + 'vuln:' + vuln
                vuln_results = api.count(query, facets=FACETS)
#                print(results)

                    #if item  in results
                    #results = api.search(query,page,minify=True)
                    #print(results)
                    # loop through the search results and pull out IP and Port and putting it in a list, result_list
                    #for result in results['facets']:
                        # add IP and Port to list
                        #vuln = result['value']
#                print(vuln_results['facets']['vuln.verified'])
                vuln_results_list = vuln_results['facets']['vuln.verified']
                if vuln_results_list:
                    for i in range(len(vuln_results_list)):
                        vuln_result = vuln_results_list[i]
#                       print(vuln_result.keys())
                        vuln = vuln_result['value']
                        query = 'net:' + ip   + ' vuln:' + vuln
                        results = api.search(query,minify=True)
                        # loop through the search results and pull out IP and Port and putting it in a list, result_list
                        for result in results['matches']:
                        # add IP and Port to list
                            result_list.append(str(result['ip_str']) + ":" + str(result['port']) + " " + vuln + "\n")


#                        result_list.sort()
                #print(result_list)
#                        print(len(result_list))
                # create a file to store new result
                #file name for exchange server
                #file1 = open(name + "_exchange_vuln.txt", "w")
                #file name for vuln search
                file1 = open(name + "_" + "_vulns.txt", "w")
                #iterate through result_list and write to file
                result = ""
                for items in result_list:
                    result = result + items
                    file1.writelines(items)
                file1.close()
                print(result)
                #send to MSteams
                #myTeamsMessage.title(name)
                #myTeamsMessage.text(result)
                #myTeamsMessage.send()
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
#print(config.load_screen)
#ask user for CVE
#vuln = input('Enter CVE name: ')

# get the campus CIDR blocks from campus.cfg file
with fileinput.FileInput(files=('campus.cfg'), mode='r') as campus_input:
    for line in campus_input:
        # print(line)
        # if the first character of the line is a digit it gets sent to the IP variable
        if line.startswith(('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')):
            ip = (line)
            shodan_query(ip, name)
        # if the first character is anything else its value gets sent to name
        else:
            name = line.strip()