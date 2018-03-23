import requests
import json

base_url='https://www.hybrid-analysis.com/api/v2'
feed_url='/feed/latest'
report_url='/search/hash'
api_key='s08000k8kcscws0o4w48gw004kwg8wcc8kw4gswgckksc00s40g4sswc0cwg0wo4'

header={'api-key':api_key}
resp=requests.get(base_url+feed_url, headers=header)
feeds=json.loads(resp.text)['data']

intel=[]
for feed in feeds:
	if(feed['threat_level_human'] in ['suspicious' , 'malicious']):
		data={'hash':feed['sha256']}
		report=requests.post(base_url+report_url, headers=header, data=data)
		intel.append(json.loads(report.text))
		