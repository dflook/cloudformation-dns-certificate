b='PhysicalResourceId'
c='Tags'
d='Status'
e='ValidationMethod'
f='.'
g='ResourceRecord'
h='I'
i='DomainName'
j='DomainValidationOptions'
k='OldResourceProperties'
m='RequestType'
n='SUCCESS'
o='DNS'
p='Certificate'
q='PENDING_VALIDATION'
r='ValidationStatus'
s='Name'
t='Type'
u='Value'
w='ResourceProperties'
x='FAILED'
y='None'
import time
import boto3
import hashlib
import json
import copy
import logging
from botocore.vendored import requests
acm=boto3.client('acm')
l=logging.getLogger()
l.setLevel(logging.INFO)
def send(event):
	l.info(event);requests.put(event['ResponseURL'],json=event)
def create_cert(props,i_token):
	a=copy.copy(props);del a['ServiceToken']
	if c in props:del a[c]
	if e in props:
		if props[e]==o:
			try:
				for name in set([props[i]]+props.get('SubjectAlternativeNames',[])):get_zone_for(name,props)
			except KeyError:raise RuntimeError('DomainValidationOptions missing')
			del a[j]
		elif props[e]=='EMAIL':del a[e]
	return acm.request_certificate(IdempotencyToken=i_token,**a)['CertificateArn']
def add_tags(arn,props):
	if c in props:acm.add_tags_to_certificate(CertificateArn=arn,Tags=props[c])
def get_zone_for(name,props):
	name=name.rstrip(f);hosted_zones={v[i].rstrip(f):v['HostedZoneId']for v in (props[j])};components=name.split(f)
	while len(components):
		if f.join(components)in hosted_zones:return hosted_zones[f.join(components)]
		components=components[1:]
	raise RuntimeError('DomainValidationOptions missing for %s'%str(name))
def validate(arn,props):
	if e in props and props[e]==o:
		all_records_created=False
		while not all_records_created:
			all_records_created=True;certificate=acm.describe_certificate(CertificateArn=arn)[p];l.info(certificate)
			if certificate[d]!=q:return
			for v in certificate[j]:
				if r not in v or g not in v:
					all_records_created=False;continue
				records=[]
				if v[r]==q:records.append({'Action':'UPSERT','ResourceRecordSet':{s:v[g][s],t:v[g][t],'TTL':60,'ResourceRecords':[{u:v[g][u]}]}})
				if records:
					response=boto3.client('route53').change_resource_record_sets(HostedZoneId=get_zone_for(v[i],props),ChangeBatch={'Comment':'Domain validation for %s'%arn,'Changes':records});l.info(response)
			time.sleep(1)
def replace_cert(event):
	old=copy.copy(event[k])
	if c in old:del old[c]
	new=copy.copy(event[w])
	if c in new:del new[c]
	return old!=new
def wait_for_issuance(arn,context):
	while context.get_remaining_time_in_millis()/1000>30:
		certificate=acm.describe_certificate(CertificateArn=arn)[p];l.info(certificate)
		if certificate[d]=='ISSUED':return True
		elif certificate[d]==x:raise RuntimeError(certificate.get('FailureReason','Failed to issue certificate'))
		time.sleep(5)
	return False
def reinvoke(event,context):
	event[h]=event.get(h,0)+1
	if event[h]>8:raise RuntimeError('Certificate not issued in time')
	l.info('Reinvoking for the %i time'%event[h]);l.info(event);boto3.client('lambda').invoke(FunctionName=context.invoked_function_arn,InvocationType='Event',Payload=json.dumps(event).encode())
def handler(event,context):
	l.info(event)
	try:
		i_token=hashlib.new('md5',(event['RequestId']+event['StackId']).encode()).hexdigest();props=event[w]
		if event[m]=='Create':
			event[b]=y;event[b]=create_cert(props,i_token);add_tags(event[b],props);validate(event[b],props)
			if wait_for_issuance(event[b],context):
				event[d]=n;return send(event)
			else:return reinvoke(event,context)
		elif event[m]=='Delete':
			if event[b]!=y:acm.delete_certificate(CertificateArn=event[b])
			event[d]=n;return send(event)
		elif event[m]=='Update':
			if replace_cert(event):
				event[b]=create_cert(props,i_token);add_tags(event[b],props);validate(event[b],props)
				if not wait_for_issuance(event[b],context):return reinvoke(event,context)
			else:
				if c in event[k]:acm.remove_tags_from_certificate(CertificateArn=event[b],Tags=event[k][c])
				add_tags(event[b],props)
			event[d]=n;return send(event)
		else:raise RuntimeError('Unknown RequestType')
	except Exception as ex:
		l.exception('');event[d]=x;event['Reason']=str(ex);return send(event)

