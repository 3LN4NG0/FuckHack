#!/usr/bin/env python
from subprocess import Popen, PIPE
print chr(27)+"[0;36m"+'''
 _____                                          
|_   _|                                         
  | | _ __  ___  ___ __ _ _ __  _ __   ___ _ __ 
  | || '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
 _| || |_) \__ \ (_| (_| | | | | | | |  __/ |   
 \___/ .__/|___/\___\__,_|_| |_|_| |_|\___|_|   
     | |                                        
     |_|                                   
     '''
print chr(27)+"[0;31m"+''' @Team-Spartan           @3LN4NG0'''
for ip in range(1,255):
	ipAddress = '192.168.0.'+str(ip)
	subprocess = Popen(['/bin/ping', '-c 1 ', ipAddress], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	stdout, stderr= subprocess.communicate(input=None)
	if "bytes from " in stdout:
		print chr(27)+"[0;34m"+"La siguiente ip esta activa %s" %(stdout.split()[1])
