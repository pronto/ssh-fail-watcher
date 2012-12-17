#!/usr/bin/env python2.6
from ConfigParser import SafeConfigParser
import glob
import codecs
import json
ignore_ip = ['75.101.142.201', '198.101.145.249', '76.21.11.37']

parser =  SafeConfigParser()
parser.read('config.ini')
for section_name in parser.sections():
    print 'Section:', section_name
    print '  Options:', parser.options(section_name)
    for name, value in parser.items(section_name):
        print '  %s = %s' % (name, value)
    print
    print

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
