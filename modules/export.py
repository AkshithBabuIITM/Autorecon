#!/usr/bin/env python3
import os
R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def export(output, data):
    if output['format'] != 'txt':
        if output['export'] == True:
            print(R + '[-]' + C + ' Invalid Output Format, Valid Formats : ' + W + 'txt, xml, csv')
            exit()
        else:
            pass
    elif output['format'] == 'txt':
        fname = output['file']
        print(Y + '[!]' + C + ' Exporting to ' + W + fname + '\n')
        with open(fname, 'w') as outfile:
            txt_export(data, outfile)
    else:
        pass
    
def txt_unpack(outfile, k, v):
    if isinstance(v, list):
        for item in v:
            if isinstance(item, list):
                outfile.write('{}\t{}\t\t{}\n'.format(*item))
            else:
                outfile.write(str(item) + '\n')
    
    elif isinstance(v, dict):
        for key, val in v.items():
            if isinstance(val, list):
                outfile.write('\n' + str(key) + '\n')
                outfile.write('='*len(key) + '\n\n')
                txt_unpack(outfile, key, val)
            else:
                outfile.write('\n' + str(key))
                outfile.write(' : ')
                outfile.write(str(val) + '\n')
    else:
        pass

def txt_export(data, outfile):
    for k, v in data.items():
        if k.startswith('module'):
            k = k.split('-')
            k = k[1]
            outfile.write('\n' + '#'*len(k) + '\n')
            outfile.write(k)
            outfile.write('\n' + '#'*len(k) + '\n')
            txt_unpack(outfile, k, v)
        else:
            outfile.write(str(k))
            outfile.write(' : ')
            outfile.write(str(v) + '\n')

#{'module-autorecon': {'Date': '2022-08-26', 'Target': 'https://civil.iitm.ac.in','IP Address': '10.24.0.190', 'Start Time': '09:55:28 AM', 'End Time': '09:55:39 AM', 'Completion Time': '0:00:11.268183'}, 
# 'module-Headers': {'Date': 'Fri, 26 Aug 2022 13:55:29 GMT', 'Server': 'Apache/2.4.18 (Ubuntu)', 'Set-Cookie': 'PHPSESSID=ah0ot9m059dhaltln94l9dip74; path=/, cookiesession1=678B2867A48304558441CAC8E9FBD261;Expires=Sat, 26 Aug 2023 13:55:29 GMT;Path=/;HttpOnly', 'Expires': 'Thu, 19 Nov 1981 08:52:00 GMT', 'Cache-Control': 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0', 'Pragma': 'no-cache', 'Vary': 'Accept-Encoding', 'Content-Encoding': 'gzip', 'Content-Length': '37030', 'Keep-Alive': 'timeout=5, max=100', 'Connection': 'Keep-Alive', 'Content-Type': 'text/html; charset=UTF-8'}, 
# 'module-Whois Lookup': {'Error': 'IPv4 address 10.24.0.190 is already defined as Private-Use Networks via RFC 1918.'},
# 'module-DNS Enumeration': {'dns': ['iitm.ac.in.             21138   IN      NS      dns2.iitm.ac.in.', 'iitm.ac.in.             21103   IN      MX      30 mailx3.iitm.ac.in.', 'iitm.ac.in.             21138   IN      MX      40 mailx4.iitm.ac.in.', 'iitm.ac.in.             21138   IN      MX      30 mailx3.iitm.ac.in.', 'iitm.ac.in.             21138   IN      NS      dns1.iitm.ac.in.', 'iitm.ac.in.             21138   IN      NS      dns3.iitm.ac.in.', 'iitm.ac.in.             21138   IN      TXT     "v=spf1 ip4:103.158.42.46/32 ip4:103.158.42.45/32 ip4:103.158.42.47/32 ip4:103.158.42.48/32 -all"', 'iitm.ac.in.             21138   IN      SOA     dns1.iitm.ac.in. root.dns1.iitm.ac.in. 2022082302 10800 3600 1814400 86400', 'iitm.ac.in.             21103   IN      MX      20 mailx2.iitm.ac.in.', 'iitm.ac.in.             21138   IN      MX      20 mailx2.iitm.ac.in.', 'iitm.ac.in.             21103   IN      MX      40 mailx4.iitm.ac.in.', 'iitm.ac.in.             1800    IN      SOA     dns1.iitm.ac.in. root.dns1.iitm.ac.in. 2022082302 10800 3600 1814400 86400', 'iitm.ac.in.             1338    IN      SOA     dns1.iitm.ac.in. root.dns1.iitm.ac.in. 2022082302 10800 3600 1814400 86400'], 'dmarc': ['DMARC Record Not Found!']}, 
# 'module-Subdomain Enumeration': {'Links': ['web.ee.iitm.ac.in', 'onlinedegree.iitm.ac.in', 'remote.iitm.ac.in', 'blog.techsoc.iitm.ac.in', 'diploma.iitm.ac.in', 'datacommons.iitm.ac.in', 'www.ioas.iitm.ac.in', 'ee5332.dev.iitm.ac.in', 'discourse.onlinedegree.iitm.ac.in', 'tcoe.iitm.ac.in', 'jup.ee5332.dev.iitm.ac.in', 'appdev.onlinedegree.iitm.ac.in', 'ioas.iitm.ac.in', 'www.joyofgiving.alumni.iitm.ac.in', 'essrv005.iitm.ac.in', 'ai4bharat.iitm.ac.in', 'ftp.iitm.ac.in', 'joyofgiving.alumni.iitm.ac.in', 'essrv006.iitm.ac.in', 'www.gjfund.iitm.ac.in', 'techsoc.iitm.ac.in', '*.iitm.ac.in', 'autodiscover.iitm.ac.in', 'ntcpwc.iitm.ac.in', 'biomimicry.iitm.ac.in', 'www.biomimicry.iitm.ac.in', 'pace.cse.iitm.ac.in', 'www.osa.iitm.ac.in', 'alumni.iitm.ac.in', 'moodle.respark.iitm.ac.in', 'giftshop.iitm.ac.in', 'backend.seek.onlinedegree.iitm.ac.in', 'seek.onlinedegree.iitm.ac.in', 'arjuna.iitm.ac.in', 'heritage.iitm.ac.in', 'bishma.iitm.ac.in', 'leap.respark.iitm.ac.in', 'gjfund.iitm.ac.in', 'placement.iitm.ac.in', 'shaastramag-uat.iitm.ac.in', 'www.cse.iitm.ac.in', 'coursesnew.iitm.ac.in', 'eegpu.dev.iitm.ac.in', 'admissions.ge.iitm.ac.in', 'www.backend.seek.onlinedegree.iitm.ac.in', 'research.iitm.ac.in', 'shaastramag.iitm.ac.in', 'www.publications.iitm.ac.in', 'moodle.ee5332.dev.iitm.ac.in', 'drone.ee2003.dev.iitm.ac.in', 'app.onlinedegree.iitm.ac.in', 'publications.iitm.ac.in', 'theory.cse.iitm.ac.in', 'bbb.evc.iitm.ac.in', 'periurban.iitm.ac.in', 'asr.iitm.ac.in', 'www.leap.respark.iitm.ac.in', 'iitm.ac.in', 'www.onlinedegree.iitm.ac.in', 'ee2003.dev.iitm.ac.in', 'www.oir.iitm.ac.in', '10x.respark.iitm.ac.in', 'r2d2.iitm.ac.in', 'courses.iitm.ac.in', 'csie.iitm.ac.in', 'instispice.iitm.ac.in', 'git.ee2003.dev.iitm.ac.in', 'hc-uat.iitm.ac.in', 'pbl.biotech.iitm.ac.in', 'osa.iitm.ac.in', 'app.diploma.iitm.ac.in', 'e-verify.acservices.iitm.ac.in', 'essrv004.iitm.ac.in', 'email.iitm.ac.in', 'keepitflowing.alumni.iitm.ac.in', 'nakula.iitm.ac.in', 'www.ee.iitm.ac.in'], 'Total Unique Sub Domains Found': '77'}, 'module-Traceroute': {'Result': [['1', '192.168.0.1', 'dlinkrouter.iitmlan'], ['2', '10.22.23.254', 'Unknown'], ['3', '10.25.100.1', 'Unknown'], ['4', '10.24.0.190', 'Unknown']], 'Protocol': 'UDP', 'Port': '33434', 'Timeout': '1.0'},
# 'module-Port Scan': {'80': 'http', '443': 'https'}}
