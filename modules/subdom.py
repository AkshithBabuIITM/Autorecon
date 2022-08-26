#!/usr/bin/env python3

import json
import aiohttp
import asyncio
import psycopg2

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

found = []

async def crtsh(hostname):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'crt.sh' + W)
	try:
		conn = psycopg2.connect(host="crt.sh",database="certwatch", user="guest", port="5432")
		conn.autocommit = True
		cur = conn.cursor()
		query = "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{}'))".format(hostname)
		cur.execute(query)
		result = cur.fetchall()
		cur.close()
		conn.close()
		for url in result:
			found.append(url[0])
	except Exception as e:
		print(R + '[-]' + C + ' crtsh Exception : ' + W + str(e))

async def anubisdb(hostname, session):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'AnubisDB' + W)
	url = 'https://jldc.me/anubis/subdomains/{}'.format(hostname)
	try:
		async with session.get(url) as resp:
			sc = resp.status
			if sc == 200:
				output = await resp.text()
				json_out = json.loads(output)
				found.extend(json_out)
			elif sc == 300:
				pass
			else:
				print(R + '[-]' + C + ' AnubisDB Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + 'AnubisDB Exception : ' + W + str(e))

async def thminer(hostname, session):
	global found
	print(Y + '[!]' + C + ' Requesting ' + G + 'ThreatMiner' + W)
	url = 'https://api.threatminer.org/v2/domain.php'
	thm_params = {
		'q': hostname,
		'rt': '5'
	}
	try:
		async with session.get(url, params=thm_params) as resp:
			sc = resp.status
			if sc == 200:
				output = await resp.text()
				json_out = json.loads(output)
				subd = json_out['results']
				found.extend(subd)
			else:
				print(R + '[-]' + C + ' ThreatMiner Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + ' ThreatMiner Exception : ' + W + str(e))

async def certspot(hostname, session):
	global found

	print(Y + '[!]' + C + ' Requesting ' + G + 'CertSpotter' + W)
	url = 'https://api.certspotter.com/v1/issuances'
	cs_params = {
		'domain': hostname,
		'expand': 'dns_names',
		'include_subdomains': 'true'
	}

	try:
		async with session.get(url, params=cs_params) as resp:
			sc = resp.status
			if sc == 200:
				json_data = await resp.text()
				json_read = json.loads(json_data)
				for i in range (0, len(json_read)):
					domains = json_read[i]['dns_names']
					found.extend(domains)
			else:
				print(R + '[-]' + C + ' CertSpotter Status : ' + W + str(sc))
	except Exception as e:
		print(R + '[-]' + C + ' CertSpotter Exception : ' + W + str(e))

async def query(hostname, tout, conf_path):
	timeout = aiohttp.ClientTimeout(total=tout)
	async with aiohttp.ClientSession(timeout=timeout) as session:
		await asyncio.gather(
			anubisdb(hostname, session),
			thminer(hostname, session),
			certspot(hostname, session),
			crtsh(hostname)
		)
	await session.close()

def subdomains(hostname, tout, output, data, conf_path):
	global found
	result = {}

	print('\n' + Y + '[!]' + Y + ' Starting Sub-Domain Enumeration...' + W + '\n')

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(query(hostname, tout, conf_path))
	loop.close()
	found = [item for item in found if item.endswith(hostname)]
	valid = r"^[A-Za-z0-9._~()'!*:@,;+?-]*$"
	import re
	found = [item for item in found if re.match(valid, item)]
	found = set(found)
	total = len(found)

	if len(found) != 0:
		print('\n' + G + '[+]' + C + ' Results : ' + W + '\n')
		for url in found:
			print(G + '[+] ' + C + url)

	print('\n' + G + '[+]' + C + ' Total Unique Sub Domains Found : ' + W + str(total))

	if output != 'None':
		result['Links'] = list(found)
		subd_output(output, data, result, total)

def subd_output(output, data, result, total):
	data['module-Subdomain Enumeration'] = result
	data['module-Subdomain Enumeration'].update({'Total Unique Sub Domains Found': str(total)})
	


'''
certspotter 

[
        {
                "id":"3827285707",
                "tbs_sha256":"dbc5640d8994b562e6183fcc3d2737963bb9d710334ecfa2546d423c3b1db1b4",
                "dns_names":["getyourrefunds.com"],
                "pubkey_sha256":"13695e809021e78b31986177076c3661b4d32bf78579bb36f04b7df875469180",
                "not_before":"2022-06-10T06:50:38Z",
                "not_after":"2022-09-08T06:50:37Z"
        }
]	

anubis 

["tanmay007100.vercel.app","migues2000.vercel.app","spectra2000.vercel.app","kevincobain2000.vercel.app","ayunami2000.vercel.app","integrator2000.vercel.app","zhugujie2000.vercel.app","uunmask2000.vercel.app","raturiabhi1000.vercel.app","swimming100.vercel.app","sriramb2000.vercel.app","millerjmiller1000.vercel.app","lh00000000.vercel.app","darindev1000.vercel.app","kishek2000.vercel.app","nihem1000.vercel.app","lahntumsi2000.vercel.app","fabs2000.vercel.app","woutervandervelde2000.vercel.app","dragon71000.vercel.app","twenty000.vercel.app","rasumi9000.vercel.app","polo0000.vercel.app","anjil0000.vercel.app","jinyu2000.vercel.app","subins2000.vercel.app","chaitrak2000.vercel.app","frankiefab100.vercel.app","circa100.vercel.app","mohsenyz2000.vercel.app","bennett000.vercel.app","fot0n2000.vercel.app","satyu000.vercel.app","srichmond3000.vercel.app","kambala3000.vercel.app","awdr74100.vercel.app","neoval100.vercel.app","rsrahul1000.vercel.app","pmatos2000.vercel.app","cappadona-1-0.vercel.app","alwyn2000.vercel.app","gabrielmartins15062000.vercel.app","herberthtk100.vercel.app","rdj2000.vercel.app","link00000000.vercel.app","nickharrison2002000.vercel.app","candy3000.vercel.app","megancooper1000.vercel.app","leekbeck100.vercel.app","kygo5000.vercel.app","keymer2000.vercel.app","olarurazvan2000.vercel.app","misters-0.vercel.app","clayton-2000.vercel.app","seregasuper2000.vercel.app","svas0000.vercel.app","scarf3000.vercel.app","canary2000.vercel.app","martind2000.vercel.app","teste000.vercel.app","kesin1202000.vercel.app","cjto2000.vercel.app","enya2000.vercel.app","narron2000.vercel.app","864451000.vercel.app","rr1000.vercel.app","daichi000.vercel.app","btogzhan2000.vercel.app","jamiebones2000.vercel.app","0-0flash0-0.vercel.app","amarandra100.vercel.app","ybs13100.vercel.app","edowning2000.vercel.app","danishboy000.vercel.app","noah2000.vercel.app","000000.vercel.app","eliecer2000.vercel.app","peperoncino000.vercel.app","jul78000.vercel.app","texas000.vercel.app","gckumar1000.vercel.app","bva100.vercel.app","bharathbarry2000.vercel.app","pyaehein000.vercel.app","tomy0000000.vercel.app","rustymagnet3000.vercel.app","tull-0.vercel.app","doanak000.vercel.app","shadowtime2000.vercel.app","do13100.vercel.app","yoshie2000.vercel.app","quik000.vercel.app","rgbh2000.vercel.app","hiphil2000.vercel.app","sibo2000.vercel.app","emilioprudon000.vercel.app","sukesh2000.vercel.app","oklsnpking100.vercel.app","donglin2000.vercel.app","merrick2000.vercel.app","senraja0000.vercel.app","kutka100.vercel.app","naeemkk10000.vercel.app","varunwalia100.vercel.app","nrobinson2000.vercel.app","marcossantosdev0000000000000000000000000.vercel.app","tyq1000.vercel.app","luispinto2000.vercel.app","wowjun-100.vercel.app","julio-0.vercel.app","stanlee1111000.vercel.app","ndailey000.vercel.app","meek2100.vercel.app","wait121000.vercel.app","netease-music-web-app-version2-0-0.vercel.app","himadu2000.vercel.app","subrat00000.vercel.app","bryan-0.vercel.app","gioelefiorenza2000.vercel.app","mdhi2000.vercel.app","aditya13042000.vercel.app","hoob72000.vercel.app","mikaeljohansson1000.vercel.app","samar-100.vercel.app","ashutoshsah-2000.vercel.app","abeeb1000.vercel.app","mmis1000.vercel.app","kashish2000.vercel.app","turchenkovadim2000.vercel.app","subhankar13022000.vercel.app","gabitron9000.vercel.app","iiak2000.vercel.app","orangewaterc1000.vercel.app","douira100.vercel.app","umajain1000.vercel.app","mmalecki-test-0.vercel.app","iyidev000.vercel.app","aarthiks2000.vercel.app","vic020100.vercel.app","minhtuan2000.vercel.app","joel352000.vercel.app","ljinkai100.vercel.app","kingpop000.vercel.app","yangzhe100.vercel.app","jamj2000.vercel.app","furryhusky1000.vercel.app","nathanf100.vercel.app","koshima2000.vercel.app","agama2000.vercel.app","chuu000.vercel.app","satoru2000.vercel.app","soft-0.vercel.app","bobby6102000.vercel.app","molotovnik000.vercel.app","gabriel-22-01-2000.vercel.app","sultan12100.vercel.app","panp2000.vercel.app","alibhai2000.vercel.app","devhive90000.vercel.app","spongle5000.vercel.app","cza100.vercel.app","soren000.vercel.app","mmk2000.vercel.app","davidma100.vercel.app","miraclousyh2000.vercel.app","test5000.vercel.app","sgkul2000.vercel.app","live-view-ver-1-0.vercel.app","alqattan2000.vercel.app","romich10000.vercel.app","hirako2000.vercel.app","shivang2000.vercel.app","iceto20032000.vercel.app","jaehwi000.vercel.app","manaenkov2000.vercel.app","sksms20000.vercel.app","naj10000.vercel.app","dhruvanita100.vercel.app","hugo13122000.vercel.app","easeee2000.vercel.app","laurent2000.vercel.app","nof1000.vercel.app","whitedwarf2000.vercel.app","avivarma100.vercel.app","6-000-000.vercel.app","grant0000.vercel.app","saurabhjangid2000.vercel.app","lemontree2000.vercel.app","bryan250000.vercel.app","mrmechanical26052000.vercel.app","sxmz2000.vercel.app","jacdx5000.vercel.app","dew00100.vercel.app","baharhamza2000.vercel.app","wmy0000.vercel.app","jcazorla2000.vercel.app","diego-d5000.vercel.app","spamathon2000.vercel.app","mrsimpson3000.vercel.app","xiejianfeng2000.vercel.app","wangziling100.vercel.app","tcs000.vercel.app","mokolotron2000.vercel.app","wholescale2000.vercel.app","gaoxin18000.vercel.app","marijnv2000.vercel.app","art256100.vercel.app","abhisinha662000.vercel.app","000scorpions000.vercel.app","luis000.vercel.app","koz31000.vercel.app","grinchuk2000.vercel.app","nishant23122000.vercel.app","cedricrobert2000.vercel.app","sulabh2000.vercel.app","fernando1000.vercel.app","react-flux-image-gallery-1-00.vercel.app","yoogi200000.vercel.app","fodox-00.vercel.app","tonychee7000.vercel.app","bhautikdonga2000.vercel.app","hr080100.vercel.app","sell9000.vercel.app","worker-test-00.vercel.app","cjavi26000.vercel.app","shuwang0000.vercel.app","alejandro28100.vercel.app","bowa1000.vercel.app","tim54000.vercel.app","nextjs-portfolio-2-0.vercel.app","kaigi100.vercel.app","eogyology2000.vercel.app","liuliu2000.vercel.app","antarctica000.vercel.app","nerd0000.vercel.app","ekko-0.vercel.app","thomas87000.vercel.app","edthedeveloper2000.vercel.app","tyrande000.vercel.app","kdanila3000.vercel.app","alejandrocruz-0.vercel.app","ghaith990000.vercel.app","mmikhail100.vercel.app","ajaybh1000.vercel.app","scuderia1000.vercel.app","ayanami3000.vercel.app","circa5000.vercel.app","riverbird-00.vercel.app","thangpd2000.vercel.app","hugomacees56000.vercel.app","leandrorosa100.vercel.app","nempey2000.vercel.app","cheonx1000.vercel.app","sreeharims2000.vercel.app","snagy22000.vercel.app","surtla100.vercel.app","atul000.vercel.app","elsy2000.vercel.app","xgamer200000000.vercel.app","umangraval2000.vercel.app","eli9000.vercel.app","jiacheng-0.vercel.app","cs1000.vercel.app","packetdog2000.vercel.app","stev-0.vercel.app","function-0.vercel.app","klay2000.vercel.app","phsiao2000.vercel.app","petrov2000andrey2000.vercel.app","hatertron3000.vercel.app","jlosco2000.vercel.app","lapis2000.vercel.app","dowvd1000.vercel.app","gokul-00.vercel.app","elvy2000.vercel.app","schapman000.vercel.app","mad9000.vercel.app","ha6000.vercel.app","11111000000.vercel.app","andy062000.vercel.app","379563000.vercel.app","kssma19942000.vercel.app","jingwang-0.vercel.app","infinitivity000.vercel.app","jonzy3000.vercel.app","harshvats2000.vercel.app","deepwayne-0.vercel.app","hemik000.vercel.app","gaurav442000.vercel.app","amritmishra2000.vercel.app","drull1000.vercel.app","dpen2000.vercel.app","trangiabao-2000.vercel.app","fredericoandrade1000.vercel.app","lbattaglioli2000.vercel.app","changers2000.vercel.app","sanya3000.vercel.app","mb47000.vercel.app","ngocthanhcr2000.vercel.app","letrung02082000.vercel.app","mendoza000.vercel.app","pauloferreira2000.vercel.app","kavman2000.vercel.app","aglide100.vercel.app","andycom12000.vercel.app","naman3100.vercel.app","arsenio262000.vercel.app","danstuart000.vercel.app","aidan-0.vercel.app","aa22041100.vercel.app","theo000.vercel.app","darkwolf45000.vercel.app","muneebkattody2000.vercel.app","akbarbobomurodov2000.vercel.app","lmiller2000.vercel.app","waldo000000.vercel.app","boom000.vercel.app","deags3000.vercel.app","flysi3000.vercel.app","ruancong100.vercel.app","dashboard-mino-wellness-2-0.vercel.app","aaditkapoor2000.vercel.app","psilon2000.vercel.app","thuybich0000.vercel.app","arivu10000.vercel.app","bingo1000.vercel.app","danpaul000.vercel.app","aury61100.vercel.app","karthikeyan2000.vercel.app","r1n0000.vercel.app","raraso2000.vercel.app","lex0000.vercel.app","dk2000.vercel.app","atec-2000.vercel.app","kmwa20042000.vercel.app","sammitpal2000.vercel.app","abhijoshi2000.vercel.app","fruit9000.vercel.app","sovereign9000.vercel.app","uzimaru0000.vercel.app","cambobambo2000.vercel.app","lulu031100.vercel.app","royallen0000.vercel.app","peeyar2000.vercel.app","0-000.vercel.app","hull9000.vercel.app","ryansui2000.vercel.app","mandy000.vercel.app","atik1000.vercel.app","sank2000.vercel.app","des3000.vercel.app","10240000.vercel.app","justin-yun-0.vercel.app","kk498100.vercel.app","kwibus2000.vercel.app","000stsysd000.vercel.app","owaissultan3000.vercel.app","testing-team-tim-2-02-0.vercel.app","ebs3000.vercel.app","lililio0000.vercel.app","shivamkataria2000.vercel.app","thanhtom26122000.vercel.app","khanhdo2000.vercel.app","marcelogames000.vercel.app","kanjaldalal1000.vercel.app","mb-log2-0.vercel.app","cyer2000.vercel.app","ferurbi2000.vercel.app","yasir2000.vercel.app","neogeo2000.vercel.app","sample1000.vercel.app","mcraz2000.vercel.app","alex1100.vercel.app","chidalgo3000.vercel.app","jiafa00000.vercel.app","nilesh2000.vercel.app","rykk0000.vercel.app","pauloj2000.vercel.app","st44100.vercel.app","valdir-alves3000.vercel.app","derise2000.vercel.app","magistar2000.vercel.app","njitram2000.vercel.app","luc2000.vercel.app","arielm1000.vercel.app","lukmannu2000.vercel.app","happy8210112000.vercel.app","rahulkashyap0000.vercel.app","andre7000.vercel.app","nicolas-castro3000.vercel.app","sray1100.vercel.app","kabeer11000.vercel.app","idmega2000.vercel.app","nmtrong1000.vercel.app","brentdierickx2000.vercel.app","fake5000.vercel.app","cjung5000.vercel.app","aurelien30000.vercel.app","dylanjames2000.vercel.app","zin2000.vercel.app","tmad4000.vercel.app","klotor1000.vercel.app","92000.vercel.app","tehmi2000.vercel.app","surajjaiswar00000.vercel.app","beavis2100.vercel.app","jie-00.vercel.app","kori2000.vercel.app","alinaqi2000.vercel.app","yangning10000.vercel.app","straykitten000.vercel.app","billyparedes-2000.vercel.app","bullet-00.vercel.app","denis-2000.vercel.app","blue-0.vercel.app","tonywong1000.vercel.app","felixtran2000.vercel.app","samuel2000.vercel.app","nandhakumar2000.vercel.app","mccj18000.vercel.app","alan10332000.vercel.app","ezd-0.vercel.app","iniobong10000.vercel.app","100001000.vercel.app","djrp2000.vercel.app","glancer000.vercel.app","josb0000.vercel.app","zorin3000.vercel.app","cosmos1000.vercel.app","aldencheng1000.vercel.app","alexei2000.vercel.app","kyang5000.vercel.app","xuansonnguyen2000.vercel.app","baohx2000.vercel.app","sserge2000.vercel.app","burhan1000.vercel.app","maslovmikhail2000.vercel.app","y3k00000.vercel.app","schulz3000.vercel.app","jw-0.vercel.app","jgadsby2000.vercel.app","madhan5000.vercel.app","nisargshah100.vercel.app","mustafaadenwala100.vercel.app","tkikuchi2000.vercel.app","mario2000.vercel.app","misha06052000.vercel.app","albrunet2000.vercel.app","clemdev2000.vercel.app","uniquetrio2000.vercel.app","cbhill252000.vercel.app","dank100.vercel.app","rajeshmondal2000.vercel.app","luis0000.vercel.app","nicotv5000.vercel.app","matheus-2000.vercel.app","puck3000.vercel.app","vitorbra2000.vercel.app","tomkuch2000.vercel.app","sergey-anishchenko2000.vercel.app","onebootcamp-1-0.vercel.app","bharathbalu2000.vercel.app","haeun0000.vercel.app","ehgks0000.vercel.app","iae-virtual-run-100.vercel.app","test1000.vercel.app","ohkr2000.vercel.app","brianaguilar000.vercel.app","13130000.vercel.app","sakurai-0000.vercel.app","crimy2000.vercel.app","vvantol2000.vercel.app","personal-projects2000.vercel.app","alexxcamargo1000.vercel.app","my-new-test-team-1000.vercel.app","pranav2612000.vercel.app","rchan0100.vercel.app","georgelinut1000.vercel.app","michas242000.vercel.app","tetra2000.vercel.app","tahmid2000.vercel.app","shauryarsinha2000.vercel.app","benpoxon2000.vercel.app","abhichakravarti2000.vercel.app","c100000000.vercel.app","ser1000.vercel.app","pingk2000.vercel.app","popo000.vercel.app","jealous000.vercel.app","neto-0-0.vercel.app","felixmedina07052000.vercel.app","zxx-0.vercel.app","mrq2000.vercel.app","surajgazi100.vercel.app","ceejay1000.vercel.app","aaronc20000.vercel.app","arkumari2000.vercel.app","pyama2000.vercel.app","coder2000.vercel.app","joozek3000.vercel.app","i20.vercel.app","ndtao2020.vercel.app","kmr600.vercel.app","meinacc20.vercel.app","anujverma000.vercel.app","test-dev-2020.vercel.app","tfvenegas10.vercel.app","dave20.vercel.app","windy00.vercel.app","kriptonsite000.vercel.app","stefka1210.vercel.app","lukechu10.vercel.app","tabe0000.vercel.app","shiro2910.vercel.app","kws60000.vercel.app","st1020.vercel.app","chuang2020.vercel.app","kuzhi1900.vercel.app","15361495220.vercel.app","deniz-2020.vercel.app","esdegan50000.vercel.app","huyhanh0810.vercel.app","manji-0.vercel.app","0x0000000.vercel.app","gubin-00.vercel.app","ajinkya2000.vercel.app","2chung-0.vercel.app","impulse2020.vercel.app","nqvinh00.vercel.app","nowsh10.vercel.app","ukayaj620.vercel.app","toonmate0000.vercel.app","wizkid220.vercel.app","itquan710.vercel.app","dendenden00.vercel.app","msert10.vercel.app","g4rry420.vercel.app","justin20.vercel.app","robertoalcantara531520.vercel.app","kkjjj0000.vercel.app","suryanshu02052000.vercel.app","wjacobs710.vercel.app","demetrio2000.vercel.app","revsoft10.vercel.app","modimrugesh1910.vercel.app","abhi10010.vercel.app","rivernchan00.vercel.app","thiagos10.vercel.app","anton10.vercel.app","ks-team.vercel.app","rem.vercel.app","titansofcnc.vercel.app","leo-checkly.vercel.app","gislawill.vercel.app","tootallnate.vercel.app","pascaliske.vercel.app","vaibhavsoni.vercel.app","zeit-github-test-dev.vercel.app","mglagola.vercel.app","skllcrn.vercel.app","zvizvi.vercel.app","mayahealth.vercel.app","luancarlos.vercel.app","verbotenberlin.vercel.app","zeit-github-test-production1.vercel.app","armurei.vercel.app","paco.vercel.app","ehtt.vercel.app","upxlabs.vercel.app","matheus.vercel.app","juan.vercel.app","class1011.vercel.app","aleksey-shmatov.vercel.app","lauf.vercel.app","efigordon.vercel.app"]

crtsh 
[('*.iitm.ac.in',), ('*.iitm.ac.in',), ('*.iitm.ac.in',), ('*.iitm.ac.in',), ('*.iitm.ac.in',), ('*.iitm.ac.in',), ('*.iitm.ac.in',), ('essrv004.iitm.ac.in',), ('essrv004.iitm.ac.in',), ('essrv004.iitm.ac.in',), ('essrv004.iitm.ac.in',), ('essrv004.iitm.ac.in',), ('essrv005.iitm.ac.in',), ('essrv005.iitm.ac.in',), ('essrv005.iitm.ac.in',), ('essrv005.iitm.ac.in',), ('essrv005.iitm.ac.in',), ('essrv006.iitm.ac.in',), ('essrv006.iitm.ac.in',), ('essrv006.iitm.ac.in',), ('essrv006.iitm.ac.in',), ('nakula.iitm.ac.in',), ('nakula.iitm.ac.in',), ('nakula.iitm.ac.in',), ('nakula.iitm.ac.in',), ('bishma.iitm.ac.in',), ('bishma.iitm.ac.in',), ('bishma.iitm.ac.in',), ('bishma.iitm.ac.in',), ('arjuna.iitm.ac.in',), ('arjuna.iitm.ac.in',), ('arjuna.iitm.ac.in',), ('arjuna.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('pace.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('www.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('theory.cse.iitm.ac.in',), ('pbl.biotech.iitm.ac.in',), ('pbl.biotech.iitm.ac.in',), ('joyofgiving.alumni.iitm.ac.in',), ('joyofgiving.alumni.iitm.ac.in',), ('joyofgiving.alumni.iitm.ac.in',), ('joyofgiving.alumni.iitm.ac.in',), ('joyofgiving.alumni.iitm.ac.in',), ('joyofgiving.alumni.iitm.ac.in',), ('www.joyofgiving.alumni.iitm.ac.in',), ('www.joyofgiving.alumni.iitm.ac.in',), ('www.joyofgiving.alumni.iitm.ac.in',), ('www.joyofgiving.alumni.iitm.ac.in',), ('www.joyofgiving.alumni.iitm.ac.in',), ('www.joyofgiving.alumni.iitm.ac.in',), ('email.iitm.ac.in',), ('email.iitm.ac.in',), ('email.iitm.ac.in',), ('email.iitm.ac.in',), ('email.iitm.ac.in',), ('email.iitm.ac.in',), ('email.iitm.ac.in',), ('email.iitm.ac.in',), ('email.iitm.ac.in',), ('autodiscover.iitm.ac.in',), ('autodiscover.iitm.ac.in',), ('autodiscover.iitm.ac.in',), ('autodiscover.iitm.ac.in',), ('autodiscover.iitm.ac.in',), ('ioas.iitm.ac.in',), ('ioas.iitm.ac.in',), ('www.ioas.iitm.ac.in',), ('www.ioas.iitm.ac.in',)]

threatminer 

{"status_code":"200","status_message":"Results found.","results":["alumni.iitm.ac.in","csie.iitm.ac.in","gjfund.iitm.ac.in","instispice.iitm.ac.in","www.gjfund.iitm.ac.in","www.oir.iitm.ac.in"]}


'''