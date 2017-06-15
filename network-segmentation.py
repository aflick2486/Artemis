#!/usr/bin/env python

################################################################################
# A network segmentation testing script that tests to see if it can find the   #
# host, and if it can, it checks to see which ports (from a list) are open.    #
################################################################################
# Written by: Adam Flickema #
#############################

import datetime
from getopt import getopt, GetoptError
import nmap
import os
import sys
import time

version = '2.0'

def usage():
    print """Network Segmentation Testing Script v%s

usage: %s

-i [filename], --import_hosts [filename]
    Specify hosts list filename.

"""%(version, sys.argv[0])


def scan():
    if len(sys.argv[1:]) == 0:
        usage()
        sys.exit(0)
    try:
        opts, args = getopt(sys.argv[1:], 'hi:', ["help", "input="])
    except GetoptError as e:
        print e
        usage()
        sys.exit(2)
    try:
        nm = nmap.PortScanner() #Represent PortScanner object
    except nmap.PortScannerError:
        #If nmap and python-nmap aren't installed
        print("Nmap not found", sys.exc_info()[0])
        sys.exit(2)
    except:
        print('Unexpected Error:', sys.exc_info()[0])
        sys.exit(2)
    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-i", "--input_hosts"):
            #Read the network blocks (127.0.0.1/30) and names(local-net) from a file
            hosts_file = a
            with open(a) as f:
                hosts = f.readlines()
    host_network = {}
    #For each network block/name, split into the block and the name and put into dictionary
    for host in hosts:
        ip, net = host.split(" ", 1)
        net = net.rstrip()
        host_network[ip] = net
    #Get the path that the script is located in and use that path to open files
    path = os.path.dirname(os.path.realpath('__file__'))
    summary = open(path + "/logs/summary.log", "w")
    #For each key, value in the dictionary
    block_count = 1
    for ip, network in host_network.iteritems():
        hosts = []
        #Determine each IP in the network block
        hosts = returnCIDR(ip)
        count = 0
        #Wait 5 minutes every network block (does wait before first one)
        if block_count > 1:
            print "Waiting 5 minutes.."
            time.sleep(60)
            print "Continuing.."
        block_count += 1
        summary.write("Scanned: " + ip + "\n")
        for host in hosts:
            date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            print "Scanning Host: " + host + "\nFrom Network: " + network + "\nTimestamp: " + date + "\n"
            #If more than 10 ips have been scanned, then wait 1 minute
            if count > 10:
                print "Waiting 1 minute to not take a network down.."
                time.sleep(60)
                print "Continuing.."
                count = 0
            else:
                #Ping Scan
                #Scan each IP
                nm.scan(hosts=host, arguments='-n -sP')
                hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
                for host, status in hosts_list:
                    #If up, run a port scan on the ip
                    if status == 'up':
                        output = path+"/logs/"+network+"_"+date+"_OPEN.log"
                        output_file = open(output, "w")
                        with open(path + '/ports_to_scan.txt') as f:
                            ports = f.readlines()
                        ports_to_scan = ''
                        for port in ports:
                            port = port.rstrip()
                            if ports_to_scan == '':
                                ports_to_scan += port
                            else:
                                ports_to_scan += ',' + port
                        #Port Scan (will take about 8 minutes for each ip)
                        nm.scan(hosts=host, arguments='-T2 -p ' + ports_to_scan)
                        for host in nm.all_hosts():
                            output_file.write('----------------------------------------------------\n')
                            print '----------------------------------------------------'
                            output_file.write('Host : %s (%s)\n' % (host, nm[host].hostname()))
                            print 'Host : %s (%s)' % (host, nm[host].hostname())
                            output_file.write('State : %s\n' % nm[host].state())
                            output_file.write('Timestamp: ' + date + "\n")
                            print 'State : %s' % nm[host].state()
                            lport = []
                            for proto in nm[host].all_protocols():
                                output_file.write('----------\n')
                                print '----------'
                                output_file.write('Protocol : %s\n' % proto)
                                print 'Protocol : %s' % proto
                                #Print the open ports in numerical order
                                lport = nm[host][proto].keys()
                            summary.write('---------------\n' + host + " is up.\n")
                        lport.sort()
                        for port in lport:
                            output_file.write('port : %s\t\t\tstate : %s\n' % (port, nm[host][proto][port]['state']))
                            print 'port : %s\tstate : %s' % (port, nm[host][proto][port]['state'])
                        output_file.write("\n")
                        output_file.close()
                count += 1
        summary.write("-------------------------------------\n")
    summary.close()
#Turn the ip into binary
def ip2bin(ip):
    b = ""
    #splits ip into 4
    inQuads = ip.split(".")
    outQuads = 4
    #For each part in ip
    for q in inQuads:
        #If part is not blank, turn it into binary and reduce the count
        if q != "": b += dec2bin(int(q),8); outQuads -= 1
    while outQuads > 0: b += "00000000"; outQuads -= 1
    return b

#Turn decimal to binary, n is each part of the ip from ip2bin.
def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1: s = "1"+s
        else: s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d: s = "0"+s
    if s == "": s = "0"
    return s

#Turn the binary back into an IP
def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

#Returns the CIDR (classless inter-domain routing) ips, or all ips in the network block
def returnCIDR(c):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    ips=[]
    if subnet == 32: return bin2ip(baseIP)
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)): ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
        return ips

if __name__ == '__main__':
    scan()
