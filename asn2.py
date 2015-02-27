import pyinotify, re, os, ConfigParser, threading, argparse, platform, sys

connections = {}
timeout = 0
attempts = 3

def ban_ip(ip, service=""):
	os.system("iptables -A INPUT -p tcp --dport ssh -s %s -j DROP" % ip)
	if(timeout != 0):
		unban = threading.Timer(timeout, unban_ip, args=[ip,]).start()

def unban_ip(ip, service=""):
	print "Unbanning ip %s" % ip
	os.system("iptables -D INPUT -p tcp --dport ssh -s %s -j DROP" % ip)

def reset_iptables():
	os.system("iptables -F")

def reset_cfg():
	pass

def get_last_lines(file):
	with open(file, "r") as f:
		f.seek(0, 2)
		fsize = f.tell()
		f.seek(max(fsize-1024, 0), 0)
		lines = f.readlines()
	lines = lines[-1:]
	for line in lines:
		if("Failed password" in line):
			return line
			break

class EventHandler(pyinotify.ProcessEvent):

	def process_IN_MODIFY(self, event):
		line = get_last_lines(event.pathname)
		if(line is not None):
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)[0]
			print "Bad SSH login from %s" % ip
			try:
				if(connections[ip] is None):
					pass
				else:
					connections[ip] += 1
					if(connections[ip] == attempts):
						ban_ip(ip)
			except KeyError:
				connections[ip] = 1

def main():
	if(platform.dist()[0] == "Ubuntu"):
		watch_file = "/var/log/auth.log"
	else:
		watch_file = "/var/log/secure"

	wm = pyinotify.WatchManager()
	handler = EventHandler()

	file_events = pyinotify.IN_MODIFY
	notifier = pyinotify.Notifier(wm, handler)
	wdd = wm.add_watch(watch_file, file_events, rec=True)

	print "running..."
	notifier.loop()

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Python IDS")
	parser.add_argument("-t", "--timeout", type=int, help="Time till IPs get unbanned in seconds")
	parser.add_argument("-a", "--attempt", type=int, help="Attempts until IPS bans IP")
	args = parser.parse_args()
	if(args.timeout is not None):
		timeout = args.timeout
	if(args.attempt is not None):
		attempts = args.attempt

	main()
