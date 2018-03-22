from twitter import Twitter, OAuth
import json
import requests
import re
import sys

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
print(intel)