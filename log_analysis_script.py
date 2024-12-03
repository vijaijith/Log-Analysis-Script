#-----------------------------------------------------------------------------------------
# Script Name: log_analysis_script
# Description: This Python script is designed for log analysis and performs the following steps:
#   1.Count Requests per IP Address
#   2.Identify the Most Frequently Accessed Endpoint
#   3.Detect Suspicious Activity
# Usage: <python log_analysis_script.py>
# Place the log file and script in the same folder before running the script.
#-----------------------------------------------------------------------------------------
from collections import Counter
from tabulate import tabulate
import re
import csv

csv_filepath= r"log_analysis_results.csv"
file_path = r"sample.log"
with open(file_path, "r") as sample:
    content = sample.read()
#-----------------------------------------------------------------------------------------
# 1. Count Requests per IP Address:
#-----------------------------------------------------------------------------------------

 # Define Regular expression to find the IP address
ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ip_addresses = re.findall(ip_regex, content)
count = Counter(ip_addresses)
sorted_counts = sorted(count.items(), key=lambda x: x[1], reverse=True)
print(tabulate(sorted_counts, headers=["IP Address", "Request Count"], tablefmt="plain" , colalign=("left", "left")))

#-----------------------------------------------------------------------------------------
#2 Identify the Most Frequently Accessed Endpoint:
#-----------------------------------------------------------------------------------------

# Define Regular expression to find the end point
endpoint_regex = r'\"[A-Z]+\s(/[\w/]+)'
endpoints = re.findall(endpoint_regex, content)
count_endpoints=Counter(endpoints)
most_visited_endpoint = max(count_endpoints, key=count_endpoints.get)
count_most_visited_endpoint = count_endpoints[most_visited_endpoint]
data_endpoint = [(most_visited_endpoint, count_most_visited_endpoint)]
print(f"\n\nMost Frequently Accessed Endpoint:\n{most_visited_endpoint} (Accessed {count_most_visited_endpoint} times)")
#print(tabulate(data_endpoint, headers=["Endpoint", "Access Count"],tablefmt="plain"))

#-----------------------------------------------------------------------------------------
#3 Detect Suspicious Activity:
#-----------------------------------------------------------------------------------------

#Define Regular expression to find (ivalid credentials)
failedlogins_regex = r'(\d+\.\d+\.\d+\.\d+).*\"POST\s(/[a-zA-Z0-9/_-]+)\sHTTP/1.1\"\s401.*(Invalid credentials)'
failedlogins = re.findall(failedlogins_regex, content)
count_failedlogins = Counter(ip for ip, _, _ in failedlogins)
data_failedlogins = [(ip, count) for ip, count in count_failedlogins.items()] #converting counter to list of tuples
flagging_threshold=10
for ip, failed_count in count_failedlogins.items():
    if(failed_count > flagging_threshold):#checking threshold value limit and failed count
        print("\n\nSuspicious Activity Detected:")
        print(tabulate(data_failedlogins, headers=["IP Address", "Failed Login Attempts"],tablefmt="plain" , colalign=("left", "left")))
        break
    else:
        print("\n\nNo Suspicious Activity Detected")
        break

#-----------------------------------------------------------------------------------------
# Write the report to csv file
#-----------------------------------------------------------------------------------------

with open(csv_filepath, mode='w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(['IP Address','Request Count'])
        writer.writerows(sorted_counts)
        
        writer.writerow([])  # Blank row for separation

        writer.writerow(['Endpoint','Access Count'])
        writer.writerows(data_endpoint)
    
        writer.writerow([])  # Blank row for separation

        for ip, failed_count in count_failedlogins.items():
            if(failed_count > flagging_threshold):
                writer.writerow(['IP Address','Failed Login Count'])
                writer.writerows(data_failedlogins)
                break
            else:
                writer.writerow(['IP Address','Failed Login Count'])
                writer.writerow(['nil','nil'])
                break