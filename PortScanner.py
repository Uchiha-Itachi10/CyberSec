#!/bin/python3

import sys
import socket
from datetime import datetime as dt

#Define our target
if len(sys.argv) == 2:
	target = socket.gethostbyname(sys.argv[1]) #Translate hostname to IPv4
else:
	print("Invalid amount of arguments.")
	print("Syntax: python3 scanner.py <IP>")

#Adding a Banner
print("-" * 50)
print("Scanning target "+target)
print("Time started: "+str(dt.now()))
print("-" * 50)

try:
	for port in range(50,85):
		  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		  socket.setdefaulttimeout(1)
		  result = s.connect_ex((target,port)) #returns an error indicator - if port is open it throws a 0, otherwise 1
		  if result == 0:
			   print("Port {} is open".format(port))
		     s.close()

#Exceptions
except KeyboardInterrupt:
	  print("\n Exiting program")
	  sys.exit()
	
except socket.gaierror:
	print("Hostname could not be resolved!")
	sys.exit()

except socket.error:
	print("Could not connect to server!!!")
	sys.exit()
