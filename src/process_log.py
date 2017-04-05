
# coding: utf-8
#import libraries
import pandas as pd
from datetime import datetime,timedelta
import warnings
warnings.filterwarnings('ignore')

#load file
def load_file(stop = 10000):
    path = "../log_input/log.txt"
    #path = "log.txt"
    with open(path,encoding='utf-8', errors='ignore') as line:
        log = line.readlines()
    log = [x.strip() for x in log]   

    #Create data frame, parse timestamp
    print ("Creating data frame ...")
    logs= pd.DataFrame() 
    row =1
    for i, line in enumerate(log):
        columns = ['host','timestamp','request' ,'reply_code','reply_bytes']
        line = line.replace("[","").replace("]","") 
        line = [x for x in line.split('"')]
        host_timestamp = [x for x in line[0].strip().split(" ") if x != "-"]
        host = host_timestamp[0]
        timestamp = host_timestamp[1] + " "+ host_timestamp[2]
        request = line[1]        
        replycode_bytes = [x for x in line[2].strip().split(" ")] 
        reply_code =replycode_bytes[0]
        reply_bytes = replycode_bytes[1]
        if (reply_bytes =="-"): reply_bytes =0
        reply_bytes = int(reply_bytes)
        logs = logs.append(pd.DataFrame(dict(zip(columns,[host,timestamp,request, reply_code,reply_bytes])),index = [i]))
        row = row+1
        if (row==stop):
            break

    logs["parsed_timestamp"] =logs["timestamp"].apply(lambda x: datetime.strptime(x,"%d/%b/%Y:%H:%M:%S -0400")) 
    return logs

def top_hosts(logs):    
    logs["host"].value_counts().to_frame().head(10).to_csv("../log_output/hosts.txt",header=None)
    print("Done ...")

#Identify the 10 resources that consume the most bandwidth on the site
def top_resources(logs):    
    resources = logs[["request", "reply_bytes"]]
    resources = resources[resources.request != 'GET / HTTP/1.0']
    resources['request'] = resources['request'].str.replace("GET", "")
    resources['request'] = resources['request'].str.replace("HTTP/1.0","")

    resources = resources.groupby('request', as_index=False).sum().sort("reply_bytes", ascending=False)
    resources["request"].head(10).to_csv("../log_output/resources.txt",header=None,index=False)
    print ("Done ...")
    
def busy_hours(logs):    
    print("Please, be patient ...")
    hours = logs[["timestamp","parsed_timestamp"]]
    hours = hours.sort(["timestamp",  "parsed_timestamp"], ascending=[True, True])
    busy_hours = pd.DataFrame()
    row =0
    #Walk through the data frame
    while row < len(hours["timestamp"]):
        index = row
        count =0
        col = row
        while col < len(hours["timestamp"]):
            dt = hours['parsed_timestamp'][col]-hours['parsed_timestamp'][index]
            count = count +1
            col = col + 1
            if (dt.seconds>3600):
                busy_hours = busy_hours.append([[hours['timestamp'][index],count]]) # Save it
                index = col #Update
                count = 0  #Reset

        row = row+1
        try:
            busy_hours = busy_hours.sort(1, ascending = [False])[:10] # Sort and update the date frame
        except (KeyError):
             pass

    busy_hours.to_csv("../log_output/hours.txt",header=None,index=False)    
    print ("Done ...")
    
#Detect patterns of three failed login attempts from the same IP address over 20 seconds
def blocked_list(logs):    
    logs = logs.sort(["host",  "parsed_timestamp"], ascending=[True, True])
    logs = logs.reset_index(drop=True)
    pattern = False
    index  = 0
    blocked = pd.DataFrame()
    for i in range(0,len(logs['reply_code'])-2, 3):

        if (logs['host'][i] is logs['host'][i+1]) is (logs['host'][i+1] is logs['host'][i+2]):
            if (logs['reply_code'][i] !='200') & (logs['reply_code'][i+1] !='200') & (logs['reply_code'][i+2] !='200'):

                dt = logs['parsed_timestamp'][i+2]-logs['parsed_timestamp'][i]
                if (dt.seconds > 20):
                    pattern = True
                    index = i+3
                    continue
        if(pattern):
            for j in range(3):
                if (logs['host'][i+j] == logs['host'][index]):
                    delta = (logs['parsed_timestamp'][i+j]-logs['parsed_timestamp'][index])
                    if (delta.seconds < 300):
                        blocked = blocked.append([[logs['host'][i+j],logs['reply_bytes'][i+j],logs['reply_code'][i+j],logs['request'][i+j],
                      logs['timestamp'][i+j]]])
                    else:
                        pattern = False #Reset
                else: pattern =False #Reset

    #Create data frame of blocked lists
    try:
        blocked [1] = blocked [1].astype(str)
        failed_list = pd.DataFrame()
        failed_list['host'] =  blocked[0] +" -- [" + blocked[4]+ "] " + ' '  + blocked[3] + ' '  + " " + blocked[2] + " " + blocked[1]
        failed_list.to_csv("../log_output/blocked.txt",header=None,index=False) 
    except (KeyError):
             pass
    print ("Done ...")   

#Load Data Frame
logs = load_file()

print ("processing the top 10 most active host/IP addresses ...")
top_hosts(logs)

print ("Processing top 10 most frequently visited in 60-minute periods ...")
busy_hours(logs)

print("processing resources that consume the most bandwidth ...")
top_resources(logs)

print ("Detect patterns of three failed login attempts from the same IP address over 20 seconds ...")
blocked_list(logs)

