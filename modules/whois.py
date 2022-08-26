#!/usr/bin/env python3

import ipwhois

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def whois_lookup(ip, output, data):
	collect = {}
	print ('\n' + Y + '[!]' + Y + ' Whois Lookup : ' + W + '\n')
	try:
		lookup = ipwhois.IPWhois(ip)
		results = lookup.lookup_whois()
		for k,v in results.items():
			if v != None:
				if isinstance(v, list):
					for item in v:
						for k, v in item.items():
							if v != None:
								print (G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
								if output != 'None':
									collect.update({str(k):str(v)})
							else:
								pass
				else:
					print (G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
					if output != 'None':
						collect.update({str(k):str(v)})
			else:
				pass

	except Exception as e:
		print (R + '[-] Error : ' + C + str(e) + W)
		if output != 'None':
			collect.update({'Error':str(e)})
		pass
	
	if output != 'None':
		whois_output(output, data, collect)

def whois_output(output, data, collect):
	data['module-Whois Lookup'] = collect
	

# {'nir': None, 
# 'asn_registry': 'arin',
#  'asn': '15169', 'asn_cidr': '142.250.0.0/15', 
# 'asn_country_code': 'US', 'asn_date': '2012-05-24', 
# 'query': '142.250.195.46', 
# 'nets': [{'cidr': '142.250.0.0/15', 'name': 'GOOGLE', 'handle': 'NET-142-250-0-0-1', 'range': '142.250.0.0 - 142.251.255.255', 'description': 'Google LLC', 'country': 'US', 'state': 'CA', 'city': 'Mountain View', 'address': '1600 Amphitheatre Parkway', 'postal_code': '94043', 'emails': ['arin-contact@google.com', 'network-abuse@google.com'], 'created': '2012-05-24', 'updated': '2012-05-24'}], 
# 'raw': None, 
# 'referral': None, 
# 'raw_referral': None}

