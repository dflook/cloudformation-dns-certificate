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
from botocore.exceptions import ClientError, ParamValidationError
from botocore.vendored import requests

acm = 0

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def send(event):
    """
    Send a response to cloudformation

    :param event: The response to send
    :type event: dict

    """

    logger.info(event)
    response = requests.put(event['ResponseURL'], json=event, headers={'content-type': ''})
    logger.info(response.content)
    response.raise_for_status()


def create_cert(props, i_token):
    """
    Create a certificate

    This create an ACM certificate and returns the Arn.
    The certificate will not yet be issued.

    :param props:
    :type props: dict[str, str]
    :param str i_token: Idempotency token
    :return: The certificate arn
    :rtype: str

    """

    api_request = copy.copy(props)

    del api_request['ServiceToken']
    api_request.pop('Region', None)
    api_request.pop('Tags', None)
    api_request.pop('Route53RoleArn', None)

    if 'ValidationMethod' in props:
        if props['ValidationMethod'] == 'DNS':

            # Check that we have all the hosted zone information we need to validate
            # before we create the certificate
            try:
                for name in set([props['DomainName']] + props.get('SubjectAlternativeNames', [])):
                    get_zone_for(name, props)
            except KeyError:
                raise RuntimeError('DomainValidationOptions' + ' missing')

            del api_request['DomainValidationOptions']

    return acm.request_certificate(
        IdempotencyToken=i_token,
        **api_request
    )['CertificateArn']


def add_tags(arn, event):
    tags = copy.copy(event['ResourceProperties'].get('Tags', []))
    tags['aws:cloudformation:' + 'logical-id'] = event['LogicalResourceId']
    tags['aws:cloudformation:' + 'stack-id'] = event['StackId']
    tags['aws:cloudformation:' + 'stack-name'] = event['StackId'].split('/')[1]

    acm.add_tags_to_certificate(**{'CertificateArn': arn, 'Tags': tags})


def get_zone_for(name, props):
    """
    Return the hosted zone to use for validating a name

    :param str name: The name to validate
    :param props: The resource properties

    :rtype: dict

    """

    name = name.rstrip('.')
    zones = {domain['DomainName'].rstrip('.'): domain for domain in props['DomainValidationOptions']}

    parts = name.split('.')

    while len(parts):
        if '.'.join(parts) in zones:
            return zones['.'.join(parts)]

        parts = parts[1:]

    raise RuntimeError('DomainValidationOptions' + ' missing' + ' for ' + name)


def validate(event, props):
    """
    Add DNS validation records for a certificate

    :param event: The cloudformation CREATE request payload
    :param props: The cloudformation certificate resource properties

    """

    if 'ValidationMethod' in props and props['ValidationMethod'] == 'DNS':

        done = False
        while not done:
            done = True

            cert = acm.describe_certificate(**{'CertificateArn':event['PhysicalResourceId']})['Certificate']
            logger.info(cert)

            if cert['Status'] != 'PENDING_VALIDATION':
                return

            for validation_option in cert['DomainValidationOptions']:

                if 'ValidationStatus' not in validation_option or 'ResourceRecord' not in validation_option:
                    done = False
                    continue

                if validation_option['ValidationStatus'] == 'PENDING_VALIDATION':
                    hosted_zone = get_zone_for(validation_option['DomainName'], props)

                    role_arn = hosted_zone.get('Route53RoleArn', props.get('Route53RoleArn', None))

                    sts = client('sts').assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=('DNSCertificate' + event['LogicalResourceId'])[:64],
                        DurationSeconds=900,
                    )['Credentials'] if role_arn is not None else {}

                    route53 = client('route53',
                        aws_access_key_id=sts.get('AccessKeyId', None),
                        aws_secret_access_key=sts.get('SecretAccessKey', None),
                        aws_session_token=sts.get('SessionToken', None),
                    ).change_resource_record_sets(**{
                        'HostedZoneId': hosted_zone['HostedZoneId'],
                        'ChangeBatch': {
                            'Comment': 'Domain validation for ' + event['PhysicalResourceId'],
                            'Changes': [{
                                'Action': 'UPSERT',
                                'ResourceRecordSet': {
                                    'Name': validation_option['ResourceRecord']['Name'],
                                    'Type': validation_option['ResourceRecord']['Type'],
                                    'TTL': 60,
                                    'ResourceRecords': [{'Value': validation_option['ResourceRecord']['Value']}],
                                },
                            }],
                        }},
                    )

                    logger.info(route53)

            time.sleep(1)


def replace_cert(event):
    """
    Does the update require replacement of the certificate

    Only tags can be updated without replacement

    :param dict event: The cloudformation Create request payload
    :rtype: bool

    """

    old = copy.copy(event['Old' + 'ResourceProperties'])
    old.pop('Tags', None)

    new = copy.copy(event['ResourceProperties'])
    new.pop('Tags', None)

    return old != new


def wait_for_issuance(arn, context):
    """
    Wait until a certificate is issued

    Returns True when issued, False when lambda execution time is up.
    If the certificate fails to issue, a RuntimeError is raised

    :param str arn: The certificate arn to wait for
    :param context: The lambda execution context
    :rtype: bool

    """

    while (context.get_remaining_time_in_millis() / 1000) > 30:

        cert = acm.describe_certificate(**{'CertificateArn': arn})['Certificate']
        logger.info(cert)

        if cert['Status'] == 'ISSUED':
            return True
        elif cert['Status'] == 'FAILED':
            raise RuntimeError(cert.get('FailureReason', 'Failed to issue certificate'))

        time.sleep(5)

    return False


def reinvoke(event, context):
    """
    Reinvoke this lambda

    The time to issue a certificate may be more than the lambda can execute for.
    This reinvokes this lambda to continue waiting.

    If this lambda has itself been reinvoked, instead raise a RuntimeError.

    :param event: lambda event to send to the new invocation
    :param context: lambda execution context

    """

    # Only Reinvoke once, which is a total of 30 minutes running
    if event.get('Reinvoked', False):
        raise RuntimeError('Certificate not issued in time')

    event['Reinvoked'] = True

    logger.info('Reinvoking')
    logger.info(event)
    client('lambda').invoke(
        FunctionName=context.invoked_function_arn,
        InvocationType='Event',
        Payload=json.dumps(event).encode()
    )

def find_certificate(arn, event):
    """
    Find the certificate if the create is cancelled

    This could happen if the stack fails and needs to rollback.
    The DELETE request will be issued before the CREATE returns the arn.

    Hopefully the CREATE is still validating but has already created tags,
    so find the certificate with the correct tag.

    :param event: The lambda event
    :rtype: str

    """

    if arn.startswith('arn:aws:acm:'):
        return arn

    for page in acm.get_paginator('list_certificates').paginate():
        for certificate in page['CertificateSummaryList']:

            tags = {tag['Key']: tag['Value'] for tag in acm.list_tags_for_certificate(**{'CertificateArn': certificate['CertificateArn']})['Tags']}
            if (tags.get('aws:cloudformation:' + 'logical-id', None) == event['LogicalResourceId'] and
                tags.get('aws:cloudformation:' + 'stack-id', None) == event['StackId']):

                return certificate['CertificateArn']

    return arn

def delete_certificate(arn, context):
    """
    Delete a certificate

    Attempts to delete a certificate. If the certificate is in use keeps trying until the lambda is
    about to timeout, then fails.

    :param str arn: The certificate to delete
    :param context: Lambda execution context

    """

    err_msg = 'Failed to delete certificate'

    while (context.get_remaining_time_in_millis() / 1000) > 30:

        try:
            acm.delete_certificate(**{'CertificateArn': arn})
            return
        except ClientError as e:
            logger.exception('Failed to delete certificate')

            err_code = e.response['Error']['Code']
            err_msg = e.response['Error']['Message']

            if err_code == 'ResourceInUseException':
                time.sleep(5)
                continue

            elif err_code in ['ResourceNotFoundException', 'ValidationException']:
                # If the arn is invalid, it didn't exist anyway.
                return

            raise

        except ParamValidationError:
            # invalid arn
            logger.exception('Failed to delete certificate')
            return

    raise RuntimeError(err_msg)

def handler(event, context):
    """
    Cloudformation custom resource handler

    :param event: lambda event payload
    :param context: lambda execution context

    """

    logger.info(event)

    try:
        i_token = hashlib.new('md5', (event['RequestId'] + event['StackId']).encode()).hexdigest()
        props = event['ResourceProperties']

        global acm
        acm = client('acm', region_name=props.get('Region', None))

        event['Status'] = 'SUCCESS'

        if event['RequestType'] == 'Create':

            if event.get('Reinvoked', False) is False:
                event['PhysicalResourceId'] = 'None'
                event['PhysicalResourceId'] = create_cert(props, i_token)
                add_tags(event['PhysicalResourceId'], event)

            validate(event, props)

            if wait_for_issuance(event['PhysicalResourceId'], context):
                return send(event)
            else:
                return reinvoke(event, context)

        elif event['RequestType'] == 'Delete':

            if event['PhysicalResourceId'] != 'None':
                delete_certificate(find_certificate(event['PhysicalResourceId'], event), context)

            return send(event)

        elif event['RequestType'] == 'Update':

            if replace_cert(event):
                if event.get('Reinvoked', False) is False:
                    event['PhysicalResourceId'] = create_cert(props, i_token)
                    add_tags(event['PhysicalResourceId'], event)

                validate(event, props)

                if not wait_for_issuance(event['PhysicalResourceId'], context):
                    return reinvoke(event, context)
            else:
                if 'Tags' in event['Old' + 'ResourceProperties']:
                    acm.remove_tags_from_certificate(**{
                        'CertificateArn': event['PhysicalResourceId'],
                        'Tags': event['Old' + 'ResourceProperties']['Tags']
                    })

                add_tags(event['PhysicalResourceId'], event)

            return send(event)

        else:
            raise RuntimeError('Unknown RequestType')

    except Exception as ex:
        logger.exception('')
        event['Status'] = 'FAILED'
        event['Reason'] = str(ex)
        return send(event)
