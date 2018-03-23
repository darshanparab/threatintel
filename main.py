from twitter import Twitter, OAuth
from copy import deepcopy
import json
import requests
import re
import csv 

def hybridanalysis(tweets):
	ha=[]
	for tweet in tweets:
		try:
			if('/sample/' in tweet['entities']['urls'][0]['expanded_url']):
					ha.append(tweet['entities']['urls'][0]['expanded_url'].split('/')[4].split('?')[0])
		except:
			pass
	return ha

def PhysicalDrive0(tweets):
	pd=[]
	regex=re.compile('(MD5\s[A-Za-z0-9]+)')
	for tweet in tweets:
			try:
				match=regex.findall(tweet['text'])
				if(len(match)!=0):
					for item in match:
						pd.append(item.split(' ')[1])
			except:
				pass
	return pd

def get_twitter_feeds(tid):
	final=[]
	access_token='228251830-ILvzB9A50V2si2AjbDD2qw7mObmxje1wX2Dr3qUd'
	access_secret='UclebAHzQzQf9vXK7S02Ets45fs9GfFZPHba58MFN21Ux'
	consumer_key='5q0swkNmkQH1YUh6T99z0xSyF'
	consumer_secret='uYxRW8diwMeOqT6eWTjTvZEf63OyWYh3sC1oQ8jO2wYmrlanBm'
	oauth=OAuth(access_token, access_secret, consumer_key, consumer_secret)
	tclient=Twitter(auth=oauth)
	tweets=list(tclient.statuses.user_timeline(screen_name=tid))
	if(tid=='hybridanalysis'):
		final=hybridanalysis(tweets)
	else:
		if(tid=='PhysicalDrive0'):
			final=PhysicalDrive0(tweets)
	del tweets
	return final

def search(salt):
	api_key='s08000k8kcscws0o4w48gw004kwg8wcc8kw4gswgckksc00s40g4sswc0cwg0wo4'
	baseurl='https://www.hybrid-analysis.com/api/v2'
	header={'api-key':api_key}
	dt={'hash':salt}
	resp=requests.post(baseurl+'/search/hash', headers=header, data=dt)
	results=json.loads(resp.text)
	return results

intel=[]
tweetsrc=open('twitters.txt','r')
for user in tweetsrc:
	user=user.replace('\n','')
	feeds=get_twitter_feeds(user)
	for feed in feeds:
		intel+=search(feed)
	del feeds
tweetsrc.close()

intelex0=[]
keys=['filename','md5','sha1','sha256','family','domain','host','vtstatus']
for threat in intel:
	temp=dict.fromkeys(keys)
	if(len(threat['domains'])!=0):
		for domain in threat['domains']:
			temp['filename']=threat['submit_name']
			temp['md5']=threat['md5']
			temp['sha1']=threat['sha1']
			temp['sha256']=threat['sha256']
			temp['domain']=domain
			temp['host']=threat['hosts']
			temp['vtstatus']=threat['av_detect']
			temp['family']=threat['vx_family']
			intelex0.append(deepcopy(temp))
	else:
		temp['filename']=threat['submit_name']
		temp['md5']=threat['md5']
		temp['sha1']=threat['sha1']
		temp['sha256']=threat['sha256']
		temp['domain']=''
		temp['host']=threat['hosts']
		temp['vtstatus']=threat['av_detect']
		temp['family']=threat['vx_family']
		intelex0.append(deepcopy(temp))	
	del temp

intelex1=[]
for threat in intelex0:
	temp=dict.fromkeys(keys)
	if(len(threat['host'])!=0):
		for host in threat['host']:
			temp['filename']=threat['filename']
			temp['md5']=threat['md5']
			temp['sha1']=threat['sha1']
			temp['sha256']=threat['sha256']
			temp['domain']=threat['domain']
			temp['host']=host
			temp['vtstatus']=threat['vtstatus']
			temp['family']=threat['family']
			intelex1.append(deepcopy(temp))
	else:
		temp['filename']=threat['filename']
		temp['md5']=threat['md5']
		temp['sha1']=threat['sha1']
		temp['sha256']=threat['sha256']
		temp['domain']=threat['domain']
		temp['host']=''
		temp['vtstatus']=threat['vtstatus']
		temp['family']=threat['family']
		intelex1.append(deepcopy(temp))	
	del temp

#intel=json.loads(intelex1)
of=open('threatintel.csv','w')
writer=csv.writer(of,delimiter=',',quotechar='"',quoting=csv.QUOTE_ALL)
for threat in intelex1:
	writer.writerow([threat['filename'],threat['md5'],threat['sha1'],threat['sha256'],threat['family'],threat['vtstatus'],threat['domain'],threat['host']])
#	writer.writerow(threat)
of.close()