import time
import boto3
import hashlib
import json
import copy
import logging
from botocore.vendored import requests

acm = boto3.client('acm')

l = logging.getLogger()
l.setLevel(logging.INFO)

def send(event):
    l.info(event)
    requests.put(event['ResponseURL'], json=event)

def create_cert(props, i_token):
    a = copy.copy(props)

    del a['ServiceToken']

    if 'Tags' in props:
        del a['Tags']

    if 'ValidationMethod' in props:
        if props['ValidationMethod'] == 'DNS':

            try:
                hosted_zones = {v['DomainName']: v['HostedZoneId'] for v in props['DomainValidationOptions']}

                for name in set([props['DomainName']] + props.get('SubjectAlternativeNames', [])):
                    if name not in hosted_zones:
                        raise RuntimeError('DomainValidationOptions missing for %s' % str(name))
            except KeyError:
                raise RuntimeError('DomainValidationOptions missing')

            del a['DomainValidationOptions']

        elif props['ValidationMethod'] == 'EMAIL':
            del a['ValidationMethod']

    arn = acm.request_certificate(
        IdempotencyToken=i_token,
        **a
    )['CertificateArn']

    if 'Tags' in props:
        acm.add_tags_to_certificate(CertificateArn=arn, Tags=props['Tags'])

    if 'ValidationMethod' in props and props['ValidationMethod'] == 'DNS':

        all_records_created = False
        while not all_records_created:

            certificate = acm.describe_certificate(CertificateArn=arn)['Certificate']
            l.info(certificate)

            all_records_created = True
            for v in certificate['DomainValidationOptions']:

                if 'ValidationStatus' not in v or 'ResourceRecord' not in v:
                    all_records_created = False
                    continue

                records = []
                if v['ValidationStatus'] == 'PENDING_VALIDATION':
                    records.append({
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': v['ResourceRecord']['Name'],
                            'Type': v['ResourceRecord']['Type'],
                            'TTL': 60,
                            'ResourceRecords': [{
                                'Value': v['ResourceRecord']['Value']
                            }]
                        }
                    })

                if records:
                    response = boto3.client('route53').change_resource_record_sets(
                        HostedZoneId=hosted_zones[v['DomainName']],
                        ChangeBatch={
                            'Comment': 'Domain validation for %s' % arn,
                            'Changes': records
                        }
                    )

                    l.info(response)

    return arn


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

        time.sleep(20)

    return False


def reinvoke(event, context):
    time.sleep((context.get_remaining_time_in_millis() / 1000) - 30)

    # Only continue to reinvoke for 8 iterations - at 300 sec timeout thats 40 mins
    event['I'] = event.get('I', 0) + 1
    if event['I'] > 8:
        raise RuntimeError('Certificate not issued in time')

    boto3.client('lambda').invoke(
        FunctionName=context.invoked_function_arn,
        InvocationType='Event',
        Payload=json.dumps(event).encode()
    )


def handler(e, c):
    l.info(e)
    try:
        i_token = hashlib.new('md5', (e['RequestId'] + e['StackId']).encode()).hexdigest()
        props = e['ResourceProperties']

        if e['RequestType'] == 'Create':
            e['PhysicalResourceId'] = 'None'
            e['PhysicalResourceId'] = create_cert(props, i_token)

            if wait_for_issuance(e['PhysicalResourceId'], c):
                e['Status'] = 'SUCCESS'
                return send(e)
            else:
                return reinvoke(e, c)

        elif e['RequestType'] == 'Delete':
            if e['PhysicalResourceId'] != 'None':
                acm.delete_certificate(CertificateArn=e['PhysicalResourceId'])
            e['Status'] = 'SUCCESS'
            return send(e)

        elif e['RequestType'] == 'Update':

            if replace_cert(e):
                e['PhysicalResourceId'] = create_cert(props, i_token)

                if not wait_for_issuance(e['PhysicalResourceId'], c):
                    return reinvoke(e, c)
            else:
                if 'Tags' in e['OldResourceProperties']:
                    acm.remove_tags_from_certificate(CertificateArn=e['PhysicalResourceId'],
                                                     Tags=e['OldResourceProperties']['Tags'])

                if 'Tags' in props:
                    acm.add_tags_to_certificate(CertificateArn=e['PhysicalResourceId'],
                                                Tags=props['Tags'])

            e['Status'] = 'SUCCESS'
            return send(e)
        else:
            raise RuntimeError('Unknown RequestType')

    except Exception as ex:
        l.exception('')
        e['Status'] = 'FAILED'
        e['Reason'] = str(ex)
        return send(e)
