#!/usr/bin/env python3

import os
import socket
import platform


R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def udp_trace(ip, port, tr_tout, output, collect):
	status = {'end': False}
	rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #socket created for listening/recieving ICMP packet 
	rx.setblocking(0)
	rx.settimeout(tr_tout)
	rx.bind(('', port))

	print('\n' + R + 'HOPS'.ljust(7) + 'IP'.ljust(17) + 'HOST' + W + '\n')

	for ttl in range(1, 31):     #ttl: Indicates the maximum number of routers the packet can traverse before the router discards the packet
		udp_send(ip, port, ttl, rx, status, tr_tout, output, collect) 
		if status['end'] == True:
			break
	rx.close()

def udp_send(ip, port, ttl, rx, status, tr_tout, output, collect):
	tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tx.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)  #socket created for sending udp packets 
	tx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	tx.setblocking(0)
	tx.settimeout(tr_tout)
	tx.sendto(''.encode(), (ip, port))   #sending udp message to host

	try:
		data,curr_addr = rx.recvfrom(512)
		curr_addr = curr_addr[0]
	except socket.error as e:
		curr_addr = '* * *'
	finally:
		tx.close()

	hop_index = str(ttl)
	hop_addr = curr_addr
	if hop_addr != '* * *':
		try:
			hop_host = socket.gethostbyaddr(hop_addr)[0] #Function to get hostname from IP
		except socket.herror:
			hop_host = 'Unknown'    #if we cant get hostname for the ip address 
	else:
		hop_addr = '* * *'
		hop_host = ''

	print(G + hop_index.ljust(7) + C + hop_addr.ljust(17) + W + hop_host)
	if output != 'None':
		collect.setdefault('Result', []).append([str(hop_index), str(hop_addr), str(hop_host)])

	if curr_addr == ip:
		status['end'] = True

def troute(ip, mode, port, tr_tout, output, data):

	if platform.system() == 'Linux':
		if os.geteuid() != 0:
			print('\n' + R + '[-]' + C + ' Root privileges are required for Traceroute, skipping...' + W)
			return
		else:
			pass
	else:
		pass

	collect = {}

	print('\n' + G + '[+]' + C + ' Port    : ' + W + str(port))
	print(G + '[+]' + C + ' Timeout : ' + W + str(tr_tout))


	if mode == 'UDP':
		print('\n' + Y + '[!]' + Y + ' Starting UDP Traceroute...' + W)
		udp_trace(ip, port, tr_tout, output, collect)
	else:
		print('\n' + R + '[-]' + C + ' Invalid Mode Selected!' + W)

	if output != 'None':
		collect['Protocol'] = mode
		collect['Port'] = str(port)
		collect['Timeout'] = str(tr_tout)
		trace_output(output, data, collect)

def trace_output(output, data, collect):
	data['module-Traceroute'] = collect
