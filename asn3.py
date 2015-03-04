#-----------------------------------------------------------------------------
#--	SOURCE FILE:	asn3.py -   A simple IDPS
#--
#--	CLASSES:		EventHandler
#--						process_IN_MODIFY()
#--					Connections
#--						increment_attempt()
#--
#--	FUNCTIONS:		def increment_attempt(self, service)
#-- 				ban_ip(ip, service)
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
#--	This script runs as an intrusion detection/prevention system that carries
#--	out the following tasks:
#-- 1) monitors the log file of user's choice through the config file
#-- 2) detects the number of attempts by a particular IP that has gone over
#--	   a user-specified limit and implements an iptables rule to ban it a 
#--	   user specified time limit
#--	3) Unbans user from iptables upon expiration of user-specified time limit 
#--
#-- The script should also be activated via crontab to run at system boot.
#-----------------------------------------------------------------------------

import pyinotify, re, os, threading, argparse
from ConfigParser import SafeConfigParser
from collections import defaultdict

CONNLIST = []
SERVICES = defaultdict()
TIMEOUT = 0
MAX_ATTEMPTS = 3
CFG_NAME = "/root/Temp/c8006-idps/idsconf"

#-----------------------------------------------------------------------------
#-- CLASS:       	EventHandler
#--
#-- FUNCTIONS:		process_IN_MODIFY(self, event)
#--
#-- NOTES: 
#-- 
#-----------------------------------------------------------------------------
class EventHandler(pyinotify.ProcessEvent):

	#-----------------------------------------------------------------------------
	#-- FUNCTION:       def process_IN_MODIFY(self, event)    
	#--
	#-- VARIABLES(S):   self - 
	#--					event - 
	#--
	#-- NOTES:
	#-- 
	#-----------------------------------------------------------------------------
	def process_IN_MODIFY(self, event):
		line = None
		for service, attr in SERVICES.iteritems():
			if event.pathname == attr[1]:
				line = get_last_lines(attr[1], attr[0])
				break

		if line is not None:
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)[0]
			if ip is not None:
				print "Bad login from %s on %s" % (ip, service)
				if len(CONNLIST) == 0:
					conn = Connections(ip)
					conn.attempts[service] += 1
					CONNLIST.append(conn)
				else:
					append = 0
					for conn in CONNLIST:
						if conn.ip == ip:
							append = 1
							conn.attempts[service] += 1
							if conn.attempts[service] >= MAX_ATTEMPTS:
								ban_ip(ip, service)
								print("Banning %s from %s" % (ip, service))
							break
					if append == 0:
						print "Appending..."
						conn = Connections(ip)
						conn.attempts[service] += 1
						CONNLIST.append(conn)

class Connections:

	def __init__(self, ip, attempts=None):
		self.ip = ip
		if attempts is None:
			self.attempts = {}
		else:
			self.attempts = attempts

		for service in SERVICES:
			self.attempts[service] = 0

#-----------------------------------------------------------------------------
#-- FUNCTION:       def ban_ip(ip, service)    
#--
#--
#-- VARIABLES(S):   ip - external client ip address to be banned
#--					service - type of service the ip is banned from
#--
#-- NOTES:
#-- This function takes in an ip and a type of service the ip is being banned
#-- from and invokes an iptable using netfilter to block the specified ip. It
#-- creates a thread that runs the fuction in a given time(in seconds). If 
#-- TIMEOUT is set (to not 0) it unbans the ip in TIMEOUT(seconds).
#-----------------------------------------------------------------------------
def ban_ip(ip, service):
	os.system("/usr/sbin/iptables -A INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))
	if(TIMEOUT != 0):
		threading.Timer(TIMEOUT, unban_ip, args=[ip,service,]).start()

#-----------------------------------------------------------------------------
#-- FUNCTION:       def unban_ip(ip, service)    
#--
#-- VARIABLES(S):   ip - external client ip address to be banned
#--					service - type of service the ip is banned from
#--
#-- NOTES:
#-- This function takes in an ip and a type of service the ip is being unbanned
#-- from and invokes an iptable using netfilter to unblock the specified ip.
#-----------------------------------------------------------------------------
def unban_ip(ip, service):
	print "Unbanning ip %s from %s" % (ip, service)
	os.system("/usr/sbin/iptables -D INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))

#-----------------------------------------------------------------------------
#-- FUNCTION:       def reset_iptables()   
#--
#-- NOTES:
#-- This function invokes iptables using netfilter to reset all IPTABLES to
#-- default.
#-----------------------------------------------------------------------------
def reset_iptables():
	os.system("/usr/sbin/iptables -F")

#-----------------------------------------------------------------------------
#-- FUNCTION:       def load_cfg()   
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
#-- VARIABLES(S):   file - the file to read
#--					keyword - specific words to inspect for
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

#-----------------------------------------------------------------------------
#-- FUNCTION:       def main()   
#--
#-- NOTES:
#-- Main function of the program.
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
	print "Each IP will have %s attempts to access each service" % MAX_ATTEMPTS
	if TIMEOUT != 0:
		print "IPs will be unbanned after %s seconds" % TIMEOUT
	else:
		print "Banned IPs will not be automatically unbanned"
	print "running..."
	notifier.loop()

# Checks if it's the main file at compile time
# Only run main() if it is
if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Python IDS")
	parser.add_argument("-t", "--TIMEOUT", type=int, help="Time till IP's get unbanned in seconds")
	parser.add_argument("-a", "--attempt", type=int, help="MAX_ATTEMPTS until IPS bans IP")
	args = parser.parse_args()
	if args.TIMEOUT is not None:
		TIMEOUT = args.TIMEOUT
	if args.attempt is not None:
		MAX_ATTEMPTS = args.attempt

	main()
