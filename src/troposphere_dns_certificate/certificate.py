"""
Lambda function backing cloudformation certificate resource

Post-minification, this module must be less than 4KiB.

"""

import copy
import hashlib
import json
import logging
import time

from boto3 import client
from botocore.vendored import requests

acm = 0

l = logging.getLogger()
l.setLevel(logging.INFO)


def send(e):
    l.info(e)
    r = requests.put(e['ResponseURL'], json=e, headers={'content-type': ''})
    l.info(r.content)
    r.raise_for_status()


def create_cert(p, i_token):
    a = copy.copy(p)

    a.pop('ServiceToken', None)
    a.pop('Region', None)
    a.pop('Tags', None)
    a.pop('Route53RoleArn', None)

    if 'ValidationMethod' in p:
        if p['ValidationMethod'] == 'DNS':

            try:
                for name in set([p['DomainName']] + p.get('SubjectAlternativeNames', [])):
                    get_zone_for(name, p)
            except KeyError:
                raise RuntimeError('DomainValidationOptions' + ' missing')

            del a['DomainValidationOptions']

        elif p['ValidationMethod'] == 'EMAIL':
            del a['ValidationMethod']

    return acm.request_certificate(
        IdempotencyToken=i_token,
        **a
    )['CertificateArn']


def add_tags(arn, p):
    if 'Tags' in p:
        acm.add_tags_to_certificate(CertificateArn=arn, Tags=p['Tags'])


def get_zone_for(name, p):
    name = name.rstrip('.')
    zones = {v['DomainName'].rstrip('.'): v['HostedZoneId'] for v in p['DomainValidationOptions']}

    parts = name.split('.')

    while len(parts):
        if '.'.join(parts) in zones:
            return zones['.'.join(parts)]

        parts = parts[1:]

    raise RuntimeError('DomainValidationOptions' + ' missing for %s' % str(name))


def validate(e, p):
    if 'ValidationMethod' in p and p['ValidationMethod'] == 'DNS':

        done = False
        while not done:
            done = True

            cert = acm.describe_certificate(CertificateArn=e['PhysicalResourceId'])['Certificate']
            l.info(cert)

            if cert['Status'] != 'PENDING_VALIDATION':
                return

            for v in cert['DomainValidationOptions']:

                if 'ValidationStatus' not in v or 'ResourceRecord' not in v:
                    done = False
                    continue

                if v['ValidationStatus'] == 'PENDING_VALIDATION':
                    c = client('sts').assume_role(
                        RoleArn=p['Route53RoleArn'],
                        RoleSessionName=('DNSCertificate'+e['LogicalResourceId'])[:64],
                        DurationSeconds=900
                    )['Credentials'] if 'Route53RoleArn' in p else {}
                    r = client('route53',
                        aws_access_key_id=c.get('AccessKeyId'),
                        aws_secret_access_key=c.get('SecretAccessKey'),
                        aws_session_token=c.get('SessionToken')
                    ).change_resource_record_sets(
                        HostedZoneId=get_zone_for(v['DomainName'], p),
                        ChangeBatch={
                            'Comment': 'Domain validation for %s' % e['PhysicalResourceId'],
                            'Changes': [{
                                'Action': 'UPSERT',
                                'ResourceRecordSet': {
                                    'Name': v['ResourceRecord']['Name'],
                                    'Type': v['ResourceRecord']['Type'],
                                    'TTL': 60,
                                    'ResourceRecords': [{
                                        'Value': v['ResourceRecord']['Value']
                                    }]
                                }
                            }]
                        }
                    )

                    l.info(r)

            time.sleep(1)


def replace_cert(event):
    old = copy.copy(event['OldResourceProperties'])
    if 'Tags' in old:
        del old['Tags']

    new = copy.copy(event['ResourceProperties'])
    if 'Tags' in new:
        del new['Tags']

    return old != new


def wait_for_issuance(arn, context):
    while (context.get_remaining_time_in_millis() / 1000) > 30:

        cert= acm.describe_certificate(CertificateArn=arn)['Certificate']
        l.info(cert)
        if cert['Status'] == 'ISSUED':
            return True
        elif cert['Status'] == 'FAILED':
            raise RuntimeError(cert.get('FailureReason', 'Failed to issue certificate'))

        time.sleep(5)

    return False


def reinvoke(event, context):
    # Only continue to reinvoke for 8 iterations
    event['I'] = event.get('I', 0) + 1
    if event['I'] > 8:
        raise RuntimeError('Certificate not issued in time')

    l.info('Reinvoking for the %i time' % event['I'])
    l.info(event)
    client('lambda').invoke(
        FunctionName=context.invoked_function_arn,
        InvocationType='Event',
        Payload=json.dumps(event).encode()
    )


def handler(event, context):
    l.info(event)
    try:
        i_token = hashlib.new('md5', (event['RequestId'] + event['StackId']).encode()).hexdigest()
        p = event['ResourceProperties']

        global acm
        acm = client('acm', region_name=p.get('Region', None))

        if event['RequestType'] == 'Create':
            event['PhysicalResourceId'] = 'None'
            event['PhysicalResourceId'] = create_cert(p, i_token)
            add_tags(event['PhysicalResourceId'], p)
            validate(event, p)

            if wait_for_issuance(event['PhysicalResourceId'], context):
                event['Status'] = 'SUCCESS'
                return send(event)
            else:
                return reinvoke(event, context)

        elif event['RequestType'] == 'Delete':
            if event['PhysicalResourceId'] != 'None':
                acm.delete_certificate(CertificateArn=event['PhysicalResourceId'])
            event['Status'] = 'SUCCESS'
            return send(event)

        elif event['RequestType'] == 'Update':

            if replace_cert(event):
                event['PhysicalResourceId'] = create_cert(p, i_token)
                add_tags(event['PhysicalResourceId'], p)
                validate(event, p)

                if not wait_for_issuance(event['PhysicalResourceId'], context):
                    return reinvoke(event, context)
            else:
                if 'Tags' in event['OldResourceProperties']:
                    acm.remove_tags_from_certificate(CertificateArn=event['PhysicalResourceId'],
                                                     Tags=event['OldResourceProperties']['Tags'])

                add_tags(event['PhysicalResourceId'], p)

            event['Status'] = 'SUCCESS'
            return send(event)
        else:
            raise RuntimeError('Unknown RequestType')

    except Exception as ex:
        l.exception('')
        event['Status'] = 'FAILED'
        event['Reason'] = str(ex)
        return send(event)
