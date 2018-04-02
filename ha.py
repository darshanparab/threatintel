import requests
import json
import time
from datetime import datetime

def hybridanalysis():
	base_url='https://www.hybrid-analysis.com/api/v2'
	feed_url='/feed/latest'
	report_url='/search/hash'
	api_key='<your_api_key>'
	header={'api-key':api_key}
	resp=requests.get(base_url+feed_url, headers=header)
	feeds=json.loads(resp.text)['data']
	of=open('hafeeds_'+datetime.strftime(datetime.today(),'%d%m%Y_%H%M%S')+'.txt','w')
	for feed in feeds:
		of.write(json.dumps(feed))
		of.write('\n')
	of.close()
	intel=[]
	for feed in feeds:
		if(feed['threat_level_human'] in ['suspicious' , 'malicious']):
			data={'hash':feed['sha256']}
			report=requests.post(base_url+report_url, headers=header, data=data)
			intel.append(json.loads(report.text))
			time.sleep(12)
	of=open('hybridanalysis_'+datetime.strftime(datetime.today(),'%d%m%Y_%H%M%S')+'.txt','w')
	for line in intel:
		of.write(json.dumps(line))
		of.write('\n')
	of.close()
	return intel

def abuse_ch_ransomware_tracker():
	base_url='https://ransomwaretracker.abuse.ch/feeds/csv/'
	resp=requests.get(base_url)
	of=open('abuse.ch_ransomware_tracker_'+datetime.strftime(datetime.today(),'%d%m%Y_%H%M%S')+'.csv','w')
	for line in resp.text.split('\n'):
		of.write(line)
		of.write('\n')
	of.close()
	
hybridanalysis()
abuse_ch_ransomware_tracker()