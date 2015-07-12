# DomainLookupwithOnlineTools (DLOT) Script by @sk3tchymoos3
# Feel free to add/remove at your leisure, see below for the dependencies. Don't forget to add your VT API key!
# sudo easy_install pip
# sudo pip install python-geoip
# sudo pip install python-geoip-geolite2
# sudo pip install simplejson

import socket, os, sys, time, simplejson, urllib, urllib2
from geoip import geolite2

#check for file name being included in the python script invocation
if len(sys.argv) < 3:
    print "Please provide the filename with domains and output file"
    sys.exit()
else:
    textfileName=sys.argv[1]
    textfileOutput=sys.argv[2]
    if os.path.exists(textfileName):
        pass
    else:
        print "File location is invalid, please double check your path"
        sys.exit()

f=open(textfileName,'r')
fOut=open(textfileOutput,'w')
for line in f:
    #first lets get the IP address for the domain
    hostname=line
    hostname=hostname.strip()
    try:
        addr=socket.gethostbyname(hostname)
    except:
        print "Error at: ", hostname
        addr="unknown"
    try:
        addr=addr.strip()
    except:
        addr="unknown"
    #ok now lets get its geoIP based on the IP
    try:
        match=geolite2.lookup(addr)
        countryCode=match.country
        #countryCode=countryCode.strip()
    except AttributeError:
        countryCode="unknown"
    # last but not least, lets see if VT has anything to say about it!
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    parameters = { "resource": hostname,
        "scan": "1",
        "apikey": "<ENTERAPIHERE>"}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    try:
        response = urllib2.urlopen(req)
        json = response.read()
        response_dict=simplejson.loads(json)
        clean = response_dict.get('positives',{})
        getLink=response_dict.get('permalink',{})
    except:
        print "Error!"
        getLink="none"
    outputToWrite= "%s , %s , %s , %s , %s\n" % (hostname,addr,countryCode,clean,getLink)
    fOut.write(outputToWrite)
    print outputToWrite
    time.sleep(15)
f.close
fOut.close

