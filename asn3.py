#-----------------------------------------------------------------------------
#--	SOURCE FILE:	asn3.py -   A simple IDPS
#--
#--	FUNCTIONS:		ban_ip(ip, service)
#--					unban_ip(ip, service)
#--					reset_iptables()
#--					load_cfg()
#--					get_last_lines(file, keyword)
#--					def process_IN_MODIFY(self, event)
#--					def process_default(self, event)
#--					def main()
#--
#--	DATE:			February 2, 2015
#--
#--	DESIGNERS:		David Wang
#--					Brij Shah
#--
#--	PROGRAMMERS:	David Wang
#--					Brij Shah
#--
#--	NOTES:
#--	
#--	
#-----------------------------------------------------------------------------

import pyinotify, re, os, threading, argparse
from ConfigParser import SafeConfigParser
from collections import defaultdict

CONNECTIONS = {}
SERVICES = defaultdict()
TIMEOUT = 0
ATTEMPTS = 3
CFG_NAME = "idsconf"

#-----------------------------------------------------------------------------
#-- FUNCTION:       def ban_ip(ip, service)    
#--
#-- DATE:           February 2, 2015
#--
#-- VARIABLES(S):   ip - external client ip address to be banned
#--					service - type of service the ip is banned from
#--
#-- DESIGNERS:      David Wang
#--					Brij Shah
#--
#-- PROGRAMMERS:    David Wang
#--					Brij Shah
#--
#-- NOTES:
#-- This function takes in an ip and a type of service the ip is being banned
#-- from and invokes an iptable using netfilter to block the specified ip. It
#-- creates a thread that runs the fuction in a given time(in seconds). If 
#-- TIMEOUT is set (to not 0) it unbans the ip in TIMEOUT(seconds).
#-----------------------------------------------------------------------------
def ban_ip(ip, service):
	os.system("iptables -A INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))
	if(TIMEOUT != 0):
		threading.Timer(TIMEOUT, unban_ip, args=[ip,service,]).start()

#-----------------------------------------------------------------------------
#-- FUNCTION:       def unban_ip(ip, service)    
#--
#-- DATE:           February 2, 2015
#--
#-- VARIABLES(S):   ip - external client ip address to be banned
#--					service - type of service the ip is banned from
#--
#-- DESIGNERS:      David Wang
#--					Brij Shah
#--
#-- PROGRAMMERS:    David Wang
#--					Brij Shah
#--
#-- NOTES:
#-- This function takes in an ip and a type of service the ip is being unbanned
#-- from and invokes an iptable using netfilter to unblock the specified ip.
#-----------------------------------------------------------------------------
def unban_ip(ip, service):
	print "Unbanning ip %s" % ip
	os.system("iptables -D INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))

#-----------------------------------------------------------------------------
#-- FUNCTION:       def reset_iptables()   
#--
#-- DATE:           February 2, 2015
#--
#-- DESIGNERS:      David Wang
#--					Brij Shah
#--
#-- PROGRAMMERS:    David Wang
#--					Brij Shah
#--
#-- NOTES:
#-- This function invokes iptables using netfilter to reset all IPTABLES to
#-- default.
#-----------------------------------------------------------------------------
def reset_iptables():
	os.system("iptables -F")

#-----------------------------------------------------------------------------
#-- FUNCTION:       def load_cfg()   
#--
#-- DATE:           February 2, 2015
#--
#-- DESIGNERS:      David Wang
#--					Brij Shah
#--
#-- PROGRAMMERS:    David Wang
#--					Brij Shah
#--
#-- NOTES:
#-- This function creates a configParser object and parses the config file to 
#-- obtain service(s) as well as keywords and log location associated with the 
#-- service. It proceeds to store the information in a list of services to 
#-- monitor. 
#-- keyword example: "FAIL LOGIN"
#-----------------------------------------------------------------------------
def load_cfg():
	parser = SafeConfigParser()
	parser.read(CFG_NAME)

	for sections in parser.sections():
		for variable, value in parser.items(sections):
			if variable == "keyword":
				keyword = value
			elif(variable == "file"):
				filepath = value
		SERVICES[sections] = [keyword, filepath]

#-----------------------------------------------------------------------------
#-- FUNCTION:       def get_last_lines(file, keyword)   
#--
#-- DATE:           February 2, 2015
#--
#-- VARIABLES(S):   file - the file to read
#--					keyword - specific words to inspect for
#--
#-- DESIGNERS:      David Wang
#--					Brij Shah
#--
#-- PROGRAMMERS:    David Wang
#--					Brij Shah
#--
#-- NOTES:
#-- This function seeks to the end of the file and returns the line that obtains 
#-- the keyword.
#-----------------------------------------------------------------------------
def get_last_lines(file, keyword):
	with open(file, "r") as f:
		f.seek(0, 2)
		fsize = f.tell()
		f.seek(max(fsize-1024, 0), 0)
		lines = f.readlines()
	lines = lines[-1:]
	for line in lines:
		if keyword in line:
			return line

class EventHandler(pyinotify.ProcessEvent):

#-----------------------------------------------------------------------------
#-- FUNCTION:       def process_IN_MODIFY(self, event)    
#--
#-- DATE:           February 2, 2015
#--
#-- VARIABLES(S):   self - 
#--					event - 
#--
#-- DESIGNERS:      David Wang
#--					Brij Shah
#--
#-- PROGRAMMERS:    David Wang
#--					Brij Shah
#--
#-- NOTES:
#-- This function 
#-----------------------------------------------------------------------------
	def process_IN_MODIFY(self, event):
		for service, attr in SERVICES.iteritems():
			if event.pathname == attr[1]:
				line = get_last_lines(attr[1], attr[0])
				break

		if line is not None:
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)[0]
			if ip is not None:
				print "Bad login from %s on %s" % (ip, service)
				try:
					if CONNECTIONS[ip] is None:
						pass
					else:
						CONNECTIONS[ip] += 1
						if(CONNECTIONS[ip] >= ATTEMPTS):
							ban_ip(ip, service)
				except KeyError:
					CONNECTIONS[ip] = 1

#-----------------------------------------------------------------------------
#-- FUNCTION:       def process_default(self, event)    
#--
#-- DATE:           February 2, 2015
#--
#-- VARIABLES(S):   self - 
#--					event - 
#--
#-- DESIGNERS:      David Wang
#--					Brij Shah
#--
#-- PROGRAMMERS:    David Wang
#--					Brij Shah
#--
#-- NOTES:
#-- This function 
#-----------------------------------------------------------------------------
	def process_default(self, event):
		print event

#-----------------------------------------------------------------------------
#-- FUNCTION:       def main()   
#--
#-- DATE:           February 2, 2015
#--
#-- DESIGNERS:      David Wang
#--					Brij Shah
#--
#-- PROGRAMMERS:    David Wang
#--					Brij Shah
#--
#-- NOTES:
#-- This function 
#-----------------------------------------------------------------------------
def main():
	load_cfg()

	wm = pyinotify.WatchManager()
	handler = EventHandler()

	file_events = pyinotify.IN_MODIFY
	notifier = pyinotify.Notifier(wm, handler)
	for service, attr in SERVICES.iteritems():
		print "Monitoring %s..." % attr[1]
		wm.add_watch(attr[1], file_events)

	print "running..."
	notifier.loop()

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Python IDS")
	parser.add_argument("-t", "--TIMEOUT", type=int, help="Time till IPs get unbanned in seconds")
	parser.add_argument("-a", "--attempt", type=int, help="ATTEMPTS until IPS bans IP")
	args = parser.parse_args()
	if args.TIMEOUT is not None:
		TIMEOUT = args.TIMEOUT
	if args.attempt is not None:
		ATTEMPTS = args.attempt
	main()
