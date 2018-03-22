import requests
import json

def vtreport(salt):
	api_key='8408d50b26782ba8362836eb5ac31d4b875df09eaeb07abd70658311813b02ab'
	report_url='https://www.virustotal.com/vtapi/v2/file/report'
	param={'apikey':api_key,'resource':salt}
	vt=requests.get(report_url,params=param)
	print(vt.text)

vtreport('825bb326b7772f88eaf5d0c785bef81ced560f52e1276e92fb26b266662c733a')
