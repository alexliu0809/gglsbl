#!/usr/bin/env python

### imports

import requests
import base64
import gzip
import hashlib
import json
import time
import math
from datetime import datetime

API_KEY = 'AIzaSyD-BupPLuPNZNnl422iLXCTkh3kozkO2Xo'
headers = {'Content-Type': 'application/json'}
PRINT = True

## get threat list categories for update request
url = 'https://safebrowsing.googleapis.com/v4/threatLists?key=' + API_KEY
thrlist = requests.get(url, headers=headers).json()


threatTypes = set()
platformTypes = set()
threatEntryTypes = set()

for thr in thrlist['threatLists']:
    threatTypes.add(thr['threatType'])
    platformTypes.add(thr['platformType'])
    threatEntryTypes.add(thr['threatEntryType'])


## Get prefixes, just get all instead of updating
allUpdateRequests = []
state = ""
for thr in thrlist['threatLists']:
    thr['constraints'] = {
      "region":                "US",
      "supportedCompressions": ["RAW"]
    }

reqdata = {
  "client": {
    "clientId":       "ucsdstudent",
    "clientVersion":  "1.0"
  },
  "listUpdateRequests": thrlist['threatLists']
}


url = 'https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key=' + API_KEY
clientStates = set()
prefixes = set()

getupd = True
while getupd:
    getupd = False   #don't do again unless there is problem with update

    updateresp = requests.post(url, headers=headers, data=json.dumps(reqdata))
    updatejson = updateresp.json()


    # get client states from threat list fetch
    for listupdate in updatejson['listUpdateResponses']:
        clientStates.add(listupdate['newClientState'])

    ### make set of all prefixes
    for listupdates in updatejson['listUpdateResponses']:
        updprefs = []
        for listupdate in listupdates['additions']: # lists by prefix length
            prefixlen = listupdate['rawHashes']['prefixSize']
            prefs = listupdate['rawHashes']['rawHashes']
            prefsb = base64.b64decode(prefs)  #binary of hashe prefixes
            prefsblist = [prefsb[i*prefixlen:(i+1)*prefixlen] for i in range(int(len(prefsb)/prefixlen))]
            for h in prefsblist:
                prefixes.add(base64.b64encode(h).decode('utf-8'))
            updprefs.extend(prefsblist)

        #verify with checksum
        prefsstr = b''.join([p for p in sorted(updprefs)])
        localcheck = base64.b64encode(hashlib.sha256(prefsstr).digest()).decode()
        if localcheck != listupdates['checksum']['sha256']:
            time.sleep(float(updatejson['minimumWaitDuration'].strip('s')))


## get the full hashes, time it
url = 'https://safebrowsing.googleapis.com/v4/fullHashes:find?key=' + API_KEY

# find all the hashes and write them to a file, benchmark time
# printWait is (max) number of times to print minWaitTime
# printBench is seconds between printing benchmark progress or -1 if don't print
def findAllHashes(printWait=0, printBench=-1):
    start_t = time.time()
    benchTime = start_t + printBench
    numreq = int(math.ceil(len(prefixes) / 500)) # round up
    findreq = {
      "client": {
        "clientId":      "ucsdstudent",
        "clientVersion": "1.0"
      },
      "clientStates": list(clientStates),
      "threatInfo": {
        "threatTypes":      list(threatTypes),
        "platformTypes":    list(platformTypes),
        "threatEntryTypes": list(threatEntryTypes),
        "threatEntries":    []  ## to be set in loop
      }
    }
    prefixeslist = list(prefixes)
    now = datetime.now()
    dumpfile = gzip.open("hashfiles/fullHashes_{}.json.gz".format(now.strftime("%Y-%m-%d")), 'w')
            
    dumpfile.write('{"responses": [')
    printWaitCount = 0

    for i in range(numreq):
        ## state progress
        if(printBench != -1 and time.time() > benchTime):
            benchTime += printBench

        reqprefixes = [{"hash": hash} for hash in prefixeslist[i*500: (i+1)*500]]
        findreq['threatInfo']['threatEntries'] = reqprefixes
        #print(findreq)

        retry = True
        while retry:
            retry = False
            try:
                findresp = requests.post(url, headers=headers, data=json.dumps(findreq)).json()
            except requests.exceptions.ConnectionError:
                retry = True
                time.sleep(1)

        #json.dump(json.dumps(findresp).strip('\n'), dumpfile)
        json.dump(findresp, dumpfile)
        dumpfile.write(',')

        # respect min wait duration
        if('minimumWaitDuration' in findresp):
            if(printWaitCount < printWait):
                printWaitCount += 1
            time.sleep(float(findresp['minimumWaitDuration'].strip('s')))

        ## make sure I don't overload my storage space
        if(dumpfile.tell() > 60000000000):
            break

    dumpfile.write("{}]}")
    dumpfile.close()

findAllHashes(printWait=20, printBench=100)
