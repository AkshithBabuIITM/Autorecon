#!/usr/bin/env python3

import socket
import threading

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def ps(ip, output, data):
	threads = []
	result = {}

	print('\n' + Y + '[!]' + Y + ' Starting Port Scan...' + W + '\n')
	print(G + '[+]' + C + ' Testing Top 3000 Ports...' + W + '\n')
	for port in range(1,1000):
		t = threading.Thread(target=sock_conn, args=[ip, port, output, result])
		t.daemon = True
		t.start()
		threads.append(t)

	for thread in threads:
		thread.join()

	if output != 'None':
		ps_output(output, data, result)

def sock_conn(ip, port, output, result):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((ip, port))
		s.close()
		service = socket.getservbyport(port, 'tcp')
		print(G + '[+] ' + C + str(port).ljust(7) + W + service.ljust(9))
		
		if output != 'None':
			result.update({str(port):service})
	except:
		s.close()
		pass

def ps_output(output, data, result):
	data['module-Port Scan'] = result
