import os
import ipaddress
#input file name


while True:
    campus = input('Enter the campus name (as shown in the Perimeter output): ')
    base_file = campus + "_base.txt"
    if os.path.exists(base_file):
        break
    else:
        print("Can not find that Campus base file. Try again.")
        continue

#open the file name, basefil
file1 = open(base_file, "r")


#read the existing file into a list
result_list = file1.readlines()
#print(result_list)

#get the IP address
while True:
    try:
        ip = ipaddress.ip_address(input('Enter the IP address ONLY (no port): '))
    except ValueError:
        print("That is not a valid IP address, try again.")
        continue
    break
#get the port
while True:
    try:
        port = int(input('Enter the Port only (no IP): '))
    except ValueError:
        print("That is not a valid Port, try again.")
        continue
    if port > 0 and port < 65536:
        break

#put ip and port together
allow_asset = str(ip) + ":" + str(port)
result_list.append(allow_asset+"\n")

#sort the list
result_list.sort()
#print(result_list)

file1 = open(base_file, "w")
#read the result_list back into the file
for items in result_list:
    file1.writelines(items)
file1.close()

print ("IP and Port " + allow_asset + " have been added to " + campus + " known external network")
