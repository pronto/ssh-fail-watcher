#!/usr/bin/env python2.6
from ConfigParser import SafeConfigParser
import glob
import codecs
import os
import sys
import re
import gzip
import socket
import GeoIP
import cPickle
import shutil
import operator
from random import choice
ignore_ip = ['75.101.142.201', '198.101.145.249', '76.21.11.37']
parser =  SafeConfigParser()
parser.read('config.ini')
newfilepath=parser.get("data-collector","rootdir")+parser.get("data-collector","datafile")
oldfilepath=parser.get("data-collector","rootdir")+parser.get("data-collector","datafile_prev")
shutil.copy2(newfilepath,oldfilepath)


def openfile(logfile):
    if 'gz' in logfile:
        celery = gzip.open(logfile, 'r')
    else:
        celery = open(logfile, 'r')
    return celery

def get_index(seq, attribute, value):
    return next(index for (index, d) in enumerate(seq) if d[attribute] == value)


def ipcheck(ip,dns):
    dns_ip=socket.gethostbyname_ex(dns)[2]
    if ip not in dns_ip:
        return "IP: "+ dns_ip[0]
    else:
        return "good"

def port_check(address, port):
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect((address, port))
        return True
    except:
        return False


if parser.get("data-collector", "use_geoip") == "yes":
    try:
        gi = GeoIP.open(parser.get("data-collector", "rootdir") + parser.get("data-collector", "geoipfile"),GeoIP.GEOIP_STANDARD)
    except:
        print "Geo ip file is not there?!"
        raise
        sys.exit()

def writelog(logtype,data):
    if parser.get("data-collector","log_changes") == 'yes':
        logfile=open(parser.get("data-collector", "rootdir")+parser.get("data-collector", "logfile"), "a")
        if logtype == "IP_NEW":
            logfile.write("New IP: "+data+"\n")
        else:
            logfile.write("Blarg: "+data+"\n")
        logfile.close()

#get which auth.log files to use
#eg ['/var/log/auth.log', '/var/log/auth.log.1', '/var/log/auth.log.4.gz', '/var/log/auth.log.3.gz', '/var/log/auth.log.2.gz']
def auth_files():
    log_list=[]
    if parser.get("data-collector", "everylogfile") == "yes":
        for files in os.listdir('/var/log'):
            if parser.get("data-collector", "auth_file") in files:
                log_list.append("/var/log/"+files)
    else:
        log_list.append("/var/log/"+parser.get("data-collector", "auth_file"))
    return log_list


#This next part scans the auth.logs, and tosses them into ip_dict, and if use_geoip is on, it does that to
#[{'IP':'321.321.321.321','geo':'mars'},{...},{...]
ip_dict=[]
for afile in auth_files():
    try:
        for line in openfile(afile):
            if "Failed" in line:
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
                if ip:
                    try:
                        index = get_index(ip_dict, 'IP', ip[0])
                        ip_dict[index]['attempts'] += choice([1,1,1,1,1,1,2,2,2,2,3,3,3,1,1,1])
                        if parser.get("data-collector", "use_geoip") ==  "yes":
                            ip_dict[index]['geo'] = gi.record_by_addr(ip[0])['country_name']
                    except:
                        ip_dict.append({"IP": ip[0], "attempts": 1})
                        writelog("IP_NEW",ip[0])
    except:
        print "please run as root....i know running things as root sucks, but auth.log needs it"
        raise
        sys.exit()

#remove IPs with less then X amount of attempts
ip_dict.sort(key=operator.itemgetter('attempts'), reverse=True)
del_attempts=[]
for a in ip_dict:
    if a['attempts'] < int(parser.get("data-collector", "removeresultsunder")):
        del_attempts.append(get_index(ip_dict,'IP',a['IP']))

del_attempts.sort(reverse=True)
for a in del_attempts:
    del ip_dict[a]
#and GONE!


#going to toss the port scaning part in another script
def fakescan(address, port):
   return choice([True,False,False])

if parser.get("data-collector", "portscan") == "yes":
    portlist=parser.get("data-collector","portstoscan").split(',')
    for ipline in ip_dict:
        index = get_index(ip_dict,'IP',ipline['IP'])
        for port in portlist:
            ip_dict[index]['Port'+port]=fakescan(ipline['IP'],port)

#compare the lists for new stuff
old_list=cPickle.load(open(oldfilepath, "rb"))
for a in ip_dict:
    try:
        index_old=get_index(old_list,'IP',a['IP'])
        index_new=get_index(ip_dict,'IP',a['IP'])
        if ip_dict[index_new]['IP'] == old_list[index_old]['IP']:
            diff = ip_dict[index_new]['attempts']-old_list[index_old]['attempts']
            ip_dict[index_new]['new']=diff
        else:
            ip_dict[index_new]['new']=0
    except:
        ip_dict[index_new]['new']=0


#debug part--- prints out ip_dict

for a in ip_dict:
    print a['IP'] + "\t" + str(a['attempts']) + "\t" + str(a['new'])


for section_name in parser.sections():
    print 'Section:', section_name
    print '  Options:', parser.options(section_name)
    for name, value in parser.items(section_name):
        print '  %s = %s' % (name, value)
    print
    print



#store the data
cPickle.dump(ip_dict,open(newfilepath,"wb"))
