#!/usr/bin/env python3

import os
import dnslib

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def dnsrec(domain, output, data):
	result = {}
	print('\n' + Y + '[!]' + Y + ' Starting DNS Enumeration...' + W + '\n')
	types = ['A', 'AAAA', 'ANY', 'CAA', 'CNAME', 'MX', 'NS', 'TXT']
	full_ans = []
	for Type in types:
		q = dnslib.DNSRecord.question(domain, Type)
		pkt = q.send('8.8.8.8', 53, tcp='UDP')
		ans = dnslib.DNSRecord.parse(pkt)
		ans = str(ans)
		ans = ans.split('\n')
		full_ans.extend(ans)
	full_ans = set(full_ans)
	dns_found = []

	for entry in full_ans:
		if entry.startswith(';') == False:
			dns_found.append(entry)
		else:
			pass
	
	if len(dns_found) != 0:
		for entry in dns_found:
			print(G + '[+]' + C + ' {}'.format(entry) + W)
			if output != 'None':
				result.setdefault('dns', []).append(entry)
	else:
		print(R + '[-]' + C + ' DNS Records Not Found!' + W)
		if output != 'None':
			result.setdefault('dns', ['DNS Records Not Found'])

	if output != 'None':
		dns_export(output, data, result)

def dns_export(output, data, result):
	data['module-DNS Enumeration'] = result

# ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33869
# ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
# ;; QUESTION SECTION:
# ;iitm.ac.in.                    IN      TXT
# ;; ANSWER SECTION:
# iitm.ac.in.             21600   IN      TXT     "v=spf1 ip4:103.158.42.46/32 ip4:103.158.42.45/32 ip4:103.158.42.47/32 ip4:103.158.42.48/32 -all"
# iitm.ac.in.             21600   IN      SOA     dns1.iitm.ac.in. root.dns1.iitm.ac.in. 2022082302 10800 3600 1814400 86400
# iitm.ac.in.             21600   IN      NS      dns1.iitm.ac.in.
# iitm.ac.in.             21600   IN      NS      dns2.iitm.ac.in.

