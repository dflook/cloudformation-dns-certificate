A='PhysicalResourceId'
B='Tags'
C='Status'
D='ValidationMethod'
E='.'
F='ResourceRecord'
G='I'
H='DomainName'
I='DomainValidationOptions'
J='OldResourceProperties'
K='RequestType'
L='SUCCESS'
M='DNS'
N='Certificate'
O='PENDING_VALIDATION'
P='ValidationStatus'
Q='Name'
R='Type'
S='Value'
T='ResourceProperties'
U='FAILED'
V='None'
import time,boto3,hashlib,json,copy,logging
from botocore.vendored import requests
acm=boto3.client('acm')
l=logging.getLogger()
l.setLevel(logging.INFO)
def send(event):
	l.info(event);r=requests.put(event['ResponseURL'],json=event,headers={'content-type':''});r.raise_for_status()
def create_cert(props,i_token):
	a=copy.copy(props);del a['ServiceToken']
	if B in props:del a[B]
	if D in props:
		if props[D]==M:
			try:
				for name in set([props[H]]+props.get('SubjectAlternativeNames',[])):get_zone_for(name,props)
			except KeyError:raise RuntimeError('DomainValidationOptions missing')
			del a[I]
		elif props[D]=='EMAIL':del a[D]
	return acm.request_certificate(IdempotencyToken=i_token,**a)['CertificateArn']
def add_tags(arn,props):
	if B in props:acm.add_tags_to_certificate(CertificateArn=arn,Tags=props[B])
def get_zone_for(name,props):
	name=name.rstrip(E);hosted_zones={v[H].rstrip(E):v['HostedZoneId']for v in(props[I])};components=name.split(E)
	while len(components):
		if E.join(components)in hosted_zones:return hosted_zones[E.join(components)]
		components=components[1:]
	raise RuntimeError('DomainValidationOptions missing for %s'%str(name))
def validate(arn,props):
	if D in props and props[D]==M:
		all_records_created=False
		while not all_records_created:
			all_records_created=True;certificate=acm.describe_certificate(CertificateArn=arn)[N];l.info(certificate)
			if certificate[C]!=O:return
			for v in certificate[I]:
				if P not in v or F not in v:
					all_records_created=False;continue
				records=[]
				if v[P]==O:records.append({'Action':'UPSERT','ResourceRecordSet':{Q:v[F][Q],R:v[F][R],'TTL':60,'ResourceRecords':[{S:v[F][S]}]}})
				if records:
					response=boto3.client('route53').change_resource_record_sets(HostedZoneId=get_zone_for(v[H],props),ChangeBatch={'Comment':'Domain validation for %s'%arn,'Changes':records});l.info(response)
			time.sleep(1)
def replace_cert(event):
	old=copy.copy(event[J])
	if B in old:del old[B]
	new=copy.copy(event[T])
	if B in new:del new[B]
	return old!=new
def wait_for_issuance(arn,context):
	while context.get_remaining_time_in_millis()/1000>30:
		certificate=acm.describe_certificate(CertificateArn=arn)[N];l.info(certificate)
		if certificate[C]=='ISSUED':return True
		elif certificate[C]==U:raise RuntimeError(certificate.get('FailureReason','Failed to issue certificate'))
		time.sleep(5)
	return False
def reinvoke(event,context):
	event[G]=event.get(G,0)+1
	if event[G]>8:raise RuntimeError('Certificate not issued in time')
	l.info('Reinvoking for the %i time'%event[G]);l.info(event);boto3.client('lambda').invoke(FunctionName=context.invoked_function_arn,InvocationType='Event',Payload=json.dumps(event).encode())
def handler(event,context):
	l.info(event)
	try:
		i_token=hashlib.new('md5',(event['RequestId']+event['StackId']).encode()).hexdigest();props=event[T]
		if event[K]=='Create':
			event[A]=V;event[A]=create_cert(props,i_token);add_tags(event[A],props);validate(event[A],props)
			if wait_for_issuance(event[A],context):
				event[C]=L;return send(event)
			else:return reinvoke(event,context)
		elif event[K]=='Delete':
			if event[A]!=V:acm.delete_certificate(CertificateArn=event[A])
			event[C]=L;return send(event)
		elif event[K]=='Update':
			if replace_cert(event):
				event[A]=create_cert(props,i_token);add_tags(event[A],props);validate(event[A],props)
				if not wait_for_issuance(event[A],context):return reinvoke(event,context)
			else:
				if B in event[J]:acm.remove_tags_from_certificate(CertificateArn=event[A],Tags=event[J][B])
				add_tags(event[A],props)
			event[C]=L;return send(event)
		else:raise RuntimeError('Unknown RequestType')
	except Exception as ex:
		l.exception('');event[C]=U;event['Reason']=str(ex);return send(event)

