#!/usr/bin/env python
#-*- coding: utf-8 -*-
# @author Distant Shock <dist.shock@secmail.pro>

from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys, getopt


def get_header():

	return r"""

	  _________                     _____   __      __         __         .__                  
	 /   _____/_____   ____   _____/ ____\ /  \    /  \_____ _/  |_  ____ |  |__   ___________ 
	 \_____  \\____ \ /  _ \ /  _ \   __\  \   \/\/   /\__  \\   __\/ ___\|  |  \_/ __ \_  __ \
	 /        \  |_> >  <_> |  <_> )  |     \        /  / __ \|  | \  \___|   Y  \  ___/|  | \/
	/_______  /   __/ \____/ \____/|__|      \__/\  /  (____  /__|  \___  >___|  /\___  >__|   
	        \/|__|                                \/        \/          \/     \/     \/       


			    |---::[ Spoof Watcher ]::---|

	"""


def get_help():

	return get_header()+r"""

|+ USAGE:

	[i] Scans network for ARP spoofers:

		"""+str(sys.argv[0])+r"""


|+ PARAMETERS:

	-h, --help
		Show this help.



	"""


class SpoofWatcher():


	def __init__(self, verbose=True):

		self.verbose = verbose


	def get_mac(self, ip):

	    # Returns the MAC address of `ip`, if it is unable to find it
	    # for some reason, throws `IndexError`
	    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
	    result = srp(p, timeout=3, verbose=False)[0]
	    return result[0][1].hwsrc


	def process(self, packet):
	    # if the packet is an ARP packet
	    if packet.haslayer(ARP):
	        # if it is an ARP response (ARP reply)
	        if packet[ARP].op == 2:
	            try:
	                # get the real MAC address of the sender
	                real_mac = get_mac(packet[ARP].psrc)
	                # get the MAC address from the packet sent to us
	                response_mac = packet[ARP].hwsrc
	                # if they're different, definetely there is an attack
	                if real_mac != response_mac:
	                	if self.verbose:
	                    	print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
	            except IndexError:
	                # unable to find the real mac
	                # may be a fake IP or firewall is blocking packets
	                pass


	def watch(self):

		try:
			sniff(store=False, prn=self.process)
		except KeyboardInterrupt:
			if self.verbose:
				print("[!] Detected CTRL+C ! Stopping Spoof Watcher, please wait...")
			exit(0)


def main():

	print(get_header())

	spoof_watcher = SpoofWatcher()
	
	res = spoof_watcher.watch()

	return res


if __name__ == "__main__":

	argv = sys.argv[1:]

	try:
		opts, args = getopt.getopt(argv, "h", ["help"])
	except getopt.GetoptError as err:
		print(get_help())
		sys.exit(2)
	if len(opts) < 1:
		print(get_help())
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h' or opt == '--help':
			print(get_help())
			sys.exit(0)

	main()

	sys.exit(0)