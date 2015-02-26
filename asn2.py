import pyinotify, re, os

watch_file = "/var/log/secure"

wm = pyinotify.WatchManager()
file_events = pyinotify.IN_MODIFY
connections = {}

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

def ban_ip(ip):
	os.system("iptables -A INPUT -s %s -j DROP" % ip)

class EventHandler(pyinotify.ProcessEvent):
	def process_IN_MODIFY(self, event):
		line = get_last_lines(event.pathname)
		if(line is not None):
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
			print "Bad SSH login from %s" % ip[0]
			try:
				if(connections[ip[0]] is None):
					pass
				else:
					connections[ip[0]] += 1
					if(connections[ip[0]] == 2):
						ban_ip(ip[0])
			except KeyError:
				connections[ip[0]] = 1



handler = EventHandler()
notifier = pyinotify.Notifier(wm, handler)
wdd = wm.add_watch(watch_file, file_events, rec=True)

print "running..."
notifier.loop()

# if __name__ == '__main__':
	# main()