"""
Lambda function backing cloudformation certificate resource

Post-minification, this module must be less than 4KiB.

"""

import copy
import hashlib
import json
import logging
import time

import boto3
from botocore.vendored import requests

acm = 0

l = logging.getLogger()
l.setLevel(logging.INFO)


def send(event):
    l.info(event)
    r = requests.put(event['ResponseURL'], json=event, headers={'content-type': ''})
    l.info(r.content)
    r.raise_for_status()


def create_cert(p, i_token):
    a = copy.copy(p)

    del a['ServiceToken']

    if 'Region' in p:
        del a['Region']

    if 'Tags' in p:
        del a['Tags']

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
    hosted_zones = {v['DomainName'].rstrip('.'): v['HostedZoneId'] for v in p['DomainValidationOptions']}

    components = name.split('.')

    while len(components):
        if '.'.join(components) in hosted_zones:
            return hosted_zones['.'.join(components)]

        components = components[1:]

    raise RuntimeError('DomainValidationOptions' + ' missing for %s' % str(name))


def validate(arn, p):
    if 'ValidationMethod' in p and p['ValidationMethod'] == 'DNS':

        all_records_created = False
        while not all_records_created:
            all_records_created = True

            certificate = acm.describe_certificate(CertificateArn=arn)['Certificate']
            l.info(certificate)

            if certificate['Status'] != 'PENDING_VALIDATION':
                return

            for v in certificate['DomainValidationOptions']:

                if 'ValidationStatus' not in v or 'ResourceRecord' not in v:
                    all_records_created = False
                    continue

                if v['ValidationStatus'] == 'PENDING_VALIDATION':
                    response = boto3.client('route53').change_resource_record_sets(
                        HostedZoneId=get_zone_for(v['DomainName'], p),
                        ChangeBatch={
                            'Comment': 'Domain validation for %s' % arn,
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

                    l.info(response)

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

        certificate = acm.describe_certificate(CertificateArn=arn)['Certificate']
        l.info(certificate)
        if certificate['Status'] == 'ISSUED':
            return True
        elif certificate['Status'] == 'FAILED':
            raise RuntimeError(certificate.get('FailureReason', 'Failed to issue certificate'))

        time.sleep(5)

    return False


def reinvoke(event, context):
    # Only continue to reinvoke for 8 iterations
    event['I'] = event.get('I', 0) + 1
    if event['I'] > 8:
        raise RuntimeError('Certificate not issued in time')

    l.info('Reinvoking for the %i time' % event['I'])
    l.info(event)
    boto3.client('lambda').invoke(
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
        acm = boto3.client('acm', region_name=p.get('Region', None))

        if event['RequestType'] == 'Create':
            event['PhysicalResourceId'] = 'None'
            event['PhysicalResourceId'] = create_cert(p, i_token)
            add_tags(event['PhysicalResourceId'], p)
            validate(event['PhysicalResourceId'], p)

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
                validate(event['PhysicalResourceId'], p)

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
