import pyinotify, re, os, ConfigParser, threading, sys, platform

connections = {}
timeout = 0

def ban_ip(ip, service=""):
	os.system("iptables -A INPUT -p tcp --dport ssh -s %s -j DROP" % ip)
	if(timeout != 0):
		unban = Timer(timeout, unban_ip, args=[ip,])

def unban_ip(ip, service=""):
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
					if(connections[ip] == 2):
						ban_ip(ip)
			except KeyError:
				connections[ip] = 1

def main():
	if(platform.dist()[0] == "Ubuntu"):
		watch_file = "/var/log/auth.log"
	else:
		watch_file = "/var/log/secure"
	wm = pyinotify.WatchManager()
	file_events = pyinotify.IN_MODIFY

	handler = EventHandler()
	notifier = pyinotify.Notifier(wm, handler)
	wdd = wm.add_watch(watch_file, file_events, rec=True)

	print "running..."
	notifier.loop()

if __name__ == '__main__':

	if(len(sys.argv) == 3):
		timeout = int(sys.argv[2])
		main()
	elif(len(sys.argv) == 1):
		main()
	else:
		print "Format: python pyIDS.py [-t timeout]"
		print "-t : Time till IPs get unbanned in seconds, default value of 0 never unbans"
