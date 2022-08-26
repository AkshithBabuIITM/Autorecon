#!/usr/bin/env python3

import requests
requests.packages.urllib3.disable_warnings()

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def headers(target, output, data):
	result = {}
	print ('\n' + Y + '[!] Headers :' + W + '\n')
	try:
		rqst = requests.get(target, verify=False, timeout=10)
		for k, v in rqst.headers.items():
			print (G + '[+]' + C + ' {} : '.format(k) + W + v)
			if output != 'None':
				result.update({k:v})
	except Exception as e:
		print('\n' + R + '[-]' + C + ' Exception : ' + W + str(e) + '\n')
		if output != 'None':
			result.update({'Exception':str(e)})

	if output != 'None':
		header_output(output, data, result)

def header_output(output, data, result):
	data['module-Headers'] = result

# Sample Response Header: 
# {'Date': 'Wed, 24 Aug 2022 11:25:14 GMT', 'Server': 'Apache/2.4.18 (Ubuntu)', 'Set-Cookie': 'PHPSESSID=rtum5jsephdrt2t4rmlemaism5; path=/, cookiesession1=678B2867AC7668326C41699E66F743C6;Expires=Thu, 24 Aug 2023 11:25:14 GMT;Path=/;HttpOnly', 'Expires': 'Thu, 19 Nov 1981 08:52:00 GMT', 'Cache-Control': 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0', 'Pragma': 'no-cache', 'Vary': 'Accept-Encoding', 'Content-Encoding': 'gzip', 'Content-Length': '37030', 'Keep-Alive': 'timeout=5, max=100', 'Connection': 'Keep-Alive', 'Content-Type': 'text/html; charset=UTF-8'}