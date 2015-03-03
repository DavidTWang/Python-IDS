import pyinotify, re, os, threading, argparse
from ConfigParser import SafeConfigParser
from collections import defaultdict

CONNLIST = []
SERVICES = defaultdict()
TIMEOUT = 0
MAX_ATTEMPTS = 3
CFG_NAME = "idsconf"

class Connections:
	ip = ""
	tries = {}

	def __init__(self, ip):
		self.ip = ip
		for service in SERVICES:
			self.tries[service] = 0

	def increment_attempt(self, service):
		self.tries[service] += 1
		return self.tries[service]

def ban_ip(ip, service):
	os.system("iptables -A INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))
	if(TIMEOUT != 0):
		threading.Timer(TIMEOUT, unban_ip, args=[ip,service,]).start()

def unban_ip(ip, service):
	print "Unbanning ip %s from %s" % (ip, service)
	os.system("iptables -D INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))

def reset_iptables():
	os.system("iptables -F")

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

	def process_IN_MODIFY(self, event):
		for service, attr in SERVICES.iteritems():
			if event.pathname == attr[1]:
				line = get_last_lines(attr[1], attr[0])
				break

		if line is not None:
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)[0]
			if ip is not None:
				if(len(CONNLIST) == 0):
					conn = Connections(ip)
					conn.increment_attempt(service)
					CONNLIST.append(conn)
				else:
					for conn in CONNLIST:
						if conn.ip == ip:
							if conn.increment_attempt(service) == MAX_ATTEMPTS:
								ban_ip(ip, service)
								print("Banning %s from %s" % (ip, service))
						else:
							CONNLIST.append(Connections(ip))
				print "Bad login from %s on %s" % (ip, service)

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
	parser.add_argument("-a", "--attempt", type=int, help="MAX_ATTEMPTS until IPS bans IP")
	args = parser.parse_args()
	if args.TIMEOUT is not None:
		TIMEOUT = args.TIMEOUT
	if args.attempt is not None:
		MAX_ATTEMPTS = args.attempt

	main()
