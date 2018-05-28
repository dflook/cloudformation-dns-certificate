b='PhysicalResourceId'
c='Tags'
d='Status'
e='ValidationMethod'
f='DomainName'
g='DomainValidationOptions'
h='ResourceRecord'
i='I'
j='OldResourceProperties'
k='RequestType'
l='SUCCESS'
m='DNS'
n='HostedZoneId'
o='Certificate'
p='PENDING_VALIDATION'
q='ValidationStatus'
r='Name'
s='Type'
t='Value'
u='ResourceProperties'
w='FAILED'
x='None'
import time
import boto3
import hashlib
import json
import copy
import logging
from botocore.vendored import requests
acm=boto3.client('acm')
logger=logging.getLogger()
logger.setLevel(logging.INFO)
def send(event):
	logger.info(event);requests.put(event['ResponseURL'],json=event)
def create_cert(props,i_token):
	a=copy.copy(props);del a['ServiceToken']
	if c in props:del a[c]
	if e in props:
		if props[e]==m:
			try:
				hosted_zones={v[f]:v[n]for v in (props[g])}
				for name in set([props[f]]+props.get('SubjectAlternativeNames',[])):
					if name not in hosted_zones:raise RuntimeError('DomainValidationOptions missing for %s'%str(name))
			except KeyError:raise RuntimeError('DomainValidationOptions missing')
			del a[g]
		elif props[e]=='EMAIL':del a[e]
	return acm.request_certificate(IdempotencyToken=i_token,**a)['CertificateArn']
def add_tags(arn,props):
	if c in props:acm.add_tags_to_certificate(CertificateArn=arn,Tags=props[c])
def validate(arn,props):
	if e in props and props[e]==m:
		hosted_zones={v[f]:v[n]for v in (props[g])};all_records_created=False
		while not all_records_created:
			all_records_created=True;certificate=acm.describe_certificate(CertificateArn=arn)[o];logger.info(certificate)
			if certificate[d]!=p:return
			for v in certificate[g]:
				if q not in v or h not in v:
					all_records_created=False;continue
				records=[]
				if v[q]==p:records.append({'Action':'UPSERT','ResourceRecordSet':{r:v[h][r],s:v[h][s],'TTL':60,'ResourceRecords':[{t:v[h][t]}]}})
				if records:
					response=boto3.client('route53').change_resource_record_sets(HostedZoneId=hosted_zones[v[f]],ChangeBatch={'Comment':'Domain validation for %s'%arn,'Changes':records});logger.info(response)
			time.sleep(1)
def replace_cert(event):
	old=copy.copy(event[j])
	if c in old:del old[c]
	new=copy.copy(event[u])
	if c in new:del new[c]
	return old!=new
def wait_for_issuance(arn,context):
	while context.get_remaining_time_in_millis()/1000>30:
		certificate=acm.describe_certificate(CertificateArn=arn)[o];logger.info(certificate)
		if certificate[d]=='ISSUED':return True
		elif certificate[d]==w:raise RuntimeError(certificate.get('FailureReason','Failed to issue certificate'))
		time.sleep(5)
	return False
def reinvoke(event,context):
	event[i]=event.get(i,0)+1
	if event[i]>8:raise RuntimeError('Certificate not issued in time')
	logger.info('Reinvoking for the %i time'%event[i]);logger.info(event);boto3.client('lambda').invoke(FunctionName=context.invoked_function_arn,InvocationType='Event',Payload=json.dumps(event).encode())
def handler(event,context):
	logger.info(event)
	try:
		i_token=hashlib.new('md5',(event['RequestId']+event['StackId']).encode()).hexdigest();props=event[u]
		if event[k]=='Create':
			event[b]=x;event[b]=create_cert(props,i_token);add_tags(event[b],props);validate(event[b],props)
			if wait_for_issuance(event[b],context):
				event[d]=l;return send(event)
			else:return reinvoke(event,context)
		elif event[k]=='Delete':
			if event[b]!=x:acm.delete_certificate(CertificateArn=event[b])
			event[d]=l;return send(event)
		elif event[k]=='Update':
			if replace_cert(event):
				event[b]=create_cert(props,i_token);add_tags(event[b],props);validate(event[b],props)
				if not wait_for_issuance(event[b],context):return reinvoke(event,context)
			else:
				if c in event[j]:acm.remove_tags_from_certificate(CertificateArn=event[b],Tags=event[j][c])
				add_tags(event[b],props)
			event[d]=l;return send(event)
		else:raise RuntimeError('Unknown RequestType')
	except Exception as ex:
		logger.exception('');event[d]=w;event['Reason']=str(ex);return send(event)
