import json
from copy import deepcopy
import re
from os import walk
from sys import exc_info
from elasticsearch import Elasticsearch

def simplify(sfd, key):
	results=[]
	for line in sfd:
		try:
			feed=json.loads(line)
		except:
			feed=line
			pass
		if(feed['threat_level_human'] in ['malicious','suspicious']):
			try:
				if(len(feed[key])>0):
					for item in feed[key]:
						temp=deepcopy(feed)
						temp[key]=item
						results.append(temp)
						del temp
				else:
					results.append(feed)
			except:
				results.append(feed)
	return results

def savetoelastic(data,docind)
	es_servers=['http://192.168.56.101:9200']
	es=Elasticsearch(es_servers)
	for entry in data:
		es.index(index=docind,doc_type='doc',body=entry)

final=[]
srcpath='.'
hafeeds=re.compile('(hafeeds_\d{8}_\d{6}\.txt)')
haintel=re.compile('(hybridanalysis_\d{8}_\d{6}\.txt)')
filelist=list(walk(srcpath))[0][2]
	
for file in filelist:
		m=hafeeds.search(file)
		try:
			if(str(type(m.group()))!="<type 'NoneType'>"):
				fd=open(file,'r')
				final=simplify(fd,'tags')
				final=simplify(final,'domains')
				final=simplify(final,'hosts')
				final=simplify(final,'processes')
				final=simplify(final,'compromised_hosts')
				final=simplify(final,'extracted_files')
				savetoelastic(final,'ti')
				fd.close()
		except:
			pass

