"""
Lambda function backing cloudformation certificate resource

Post-minification, this module must be less than 4KiB.

"""

import time
import boto3
import hashlib
import json
import copy
import logging
from botocore.vendored import requests

acm = boto3.client('acm')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def send(event):
    logger.info(event)
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

    return acm.request_certificate(
        IdempotencyToken=i_token,
        **a
    )['CertificateArn']

def add_tags(arn, props):
    if 'Tags' in props:
        acm.add_tags_to_certificate(CertificateArn=arn, Tags=props['Tags'])

def validate(arn, props):
    if 'ValidationMethod' in props and props['ValidationMethod'] == 'DNS':

        hosted_zones = {v['DomainName']: v['HostedZoneId'] for v in props['DomainValidationOptions']}

        all_records_created = False
        while not all_records_created:
            all_records_created = True

            certificate = acm.describe_certificate(CertificateArn=arn)['Certificate']
            logger.info(certificate)

            if certificate['Status'] != 'PENDING_VALIDATION':
                return

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

                    logger.info(response)

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
        logger.info(certificate)
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

    logger.info('Reinvoking for the %i time' % event['I'])
    logger.info(event)
    boto3.client('lambda').invoke(
        FunctionName=context.invoked_function_arn,
        InvocationType='Event',
        Payload=json.dumps(event).encode()
    )


def handler(event, context):
    logger.info(event)
    try:
        i_token = hashlib.new('md5', (event['RequestId'] + event['StackId']).encode()).hexdigest()
        props = event['ResourceProperties']

        if event['RequestType'] == 'Create':
            event['PhysicalResourceId'] = 'None'
            event['PhysicalResourceId'] = create_cert(props, i_token)
            add_tags(event['PhysicalResourceId'], props)
            validate(event['PhysicalResourceId'], props)

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
                event['PhysicalResourceId'] = create_cert(props, i_token)
                add_tags(event['PhysicalResourceId'], props)
                validate(event['PhysicalResourceId'], props)

                if not wait_for_issuance(event['PhysicalResourceId'], context):
                    return reinvoke(event, context)
            else:
                if 'Tags' in event['OldResourceProperties']:
                    acm.remove_tags_from_certificate(CertificateArn=event['PhysicalResourceId'],
                                                     Tags=event['OldResourceProperties']['Tags'])

                add_tags(event['PhysicalResourceId'], props)

            event['Status'] = 'SUCCESS'
            return send(event)
        else:
            raise RuntimeError('Unknown RequestType')

    except Exception as ex:
        logger.exception('')
        event['Status'] = 'FAILED'
        event['Reason'] = str(ex)
        return send(event)
