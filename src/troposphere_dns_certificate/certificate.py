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

logger = logging.getLogger()
logger.setLevel(logging.INFO)

log_info = logger.info
log_exception = logger.exception

def handler(e, c):
    """
    Cloudformation custom resource handler

    :param e: lambda event payload
    :param c: lambda execution context

    """

    log_info(e)

    def request_cert():
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
                        get_zone_for(name)
                except KeyError:
                    raise RuntimeError('DomainValidationOptions' + ' missing')

                del api_request['DomainValidationOptions']

        return acm.request_certificate(
            IdempotencyToken=i_token,
            **api_request
        )['CertificateArn']

    def delete_certificate(a):
        """
        Delete a certificate

        Attempts to delete a certificate. If the certificate is in use keeps trying until the lambda is
        about to timeout, then fails.

        :param str a: The certificate to delete
        :param context: Lambda execution context

        """

        err_msg = 'Failed to delete certificate'

        while (c.get_remaining_time_in_millis() / 1000) > 30:

            try:
                acm.delete_certificate(**{'CertificateArn': a})
                return
            except ClientError as exception:
                log_exception('Failed to delete certificate')

                err_code = exception.response['Error']['Code']
                err_msg = exception.response['Error']['Message']

                if err_code == 'ResourceInUseException':
                    time.sleep(5)
                    continue

                elif err_code in ['ResourceNotFoundException', 'ValidationException']:
                    # If the arn is invalid, it didn't exist anyway.
                    return

                raise

            except ParamValidationError:
                # invalid arn
                log_exception('Failed to delete certificate')
                return

        raise RuntimeError(err_msg)

    def find_certificate(a):
        """
        Find the certificate if the create is cancelled

        This could happen if the stack fails and needs to rollback.
        The DELETE request will be issued before the CREATE returns the arn.

        Hopefully the CREATE is still validating but has already created tags,
        so find the certificate with the correct tag.

        :param event: The lambda event
        :rtype: str

        """

        if a.startswith('arn:'):
            return a

        for page in acm.get_paginator('list_certificates').paginate():
            for certificate in page['CertificateSummaryList']:

                tags = {tag['Key']: tag['Value'] for tag in
                        acm.list_tags_for_certificate(**{'CertificateArn': certificate['CertificateArn']})['Tags']}

                if (tags.get('cloudformation:' + 'logical-id') == e['LogicalResourceId'] and
                        tags.get('cloudformation:' + 'stack-id') == e['StackId']):
                    return certificate['CertificateArn']

        return a

    def reinvoke():
        """
        Reinvoke this lambda

        The time to issue a certificate may be more than the lambda can execute for.
        This reinvokes this lambda to continue waiting.

        If this lambda has itself been reinvoked, instead raise a RuntimeError.

        :param event: lambda event to send to the new invocation
        :param context: lambda execution context

        """

        # Only Reinvoke once, which is a total of 30 minutes running
        if e.get('Reinvoked', False):
            raise RuntimeError('Certificate not issued in time')

        e['Reinvoked'] = True

        log_info('Reinvoked')
        log_info(e)
        client('lambda').invoke(
            FunctionName=c.invoked_function_arn,
            InvocationType='Event',
            Payload=json.dumps(e).encode()
        )

    def wait_for_issuance(a):
        """
        Wait until a certificate is issued

        Returns True when issued, False when lambda execution time is up.
        If the certificate fails to issue, a RuntimeError is raised

        :param str a: The certificate arn to wait for
        :param context: The lambda execution context
        :rtype: bool

        """

        while (c.get_remaining_time_in_millis() / 1000) > 30:

            cert = acm.describe_certificate(**{'CertificateArn': a})['Certificate']
            log_info(cert)

            if cert['Status'] == 'ISSUED':
                return True
            elif cert['Status'] == 'FAILED':
                raise RuntimeError(cert.get('FailureReason', 'Failed to issue certificate'))

            time.sleep(5)

        return False

    def replace_cert():
        """
        Does the update require replacement of the certificate

        Only tags can be updated without replacement

        :param dict event: The cloudformation Create request payload
        :rtype: bool

        """

        old = copy.copy(e['Old' + 'ResourceProperties'])
        old.pop('Tags', None)

        new = copy.copy(e['ResourceProperties'])
        new.pop('Tags', None)

        return old != new

    def validate():
        """
        Add DNS validation records for a certificate

        :param event: The cloudformation CREATE request payload
        :param props: The cloudformation certificate resource properties

        """

        if 'ValidationMethod' in props and props['ValidationMethod'] == 'DNS':

            done = False
            while not done:
                done = True

                cert = acm.describe_certificate(**{'CertificateArn': e['PhysicalResourceId']})['Certificate']
                log_info(cert)

                if cert['Status'] != 'PENDING_VALIDATION':
                    return

                for validation_option in cert['DomainValidationOptions']:

                    if 'ValidationStatus' not in validation_option or 'ResourceRecord' not in validation_option:
                        done = False
                        continue

                    if validation_option['ValidationStatus'] == 'PENDING_VALIDATION':
                        hosted_zone = get_zone_for(validation_option['DomainName'])

                        role_arn = hosted_zone.get('Route53RoleArn', props.get('Route53RoleArn'))

                        sts = client('sts').assume_role(
                            RoleArn=role_arn,
                            RoleSessionName=('Certificate' + e['LogicalResourceId'])[:64],
                            DurationSeconds=900,
                        )['Credentials'] if role_arn is not None else {}

                        route53 = client('route53',
                            aws_access_key_id=sts.get('AccessKeyId'),
                            aws_secret_access_key=sts.get('SecretAccessKey'),
                            aws_session_token=sts.get('SessionToken'),
                        ).change_resource_record_sets(**{
                            'HostedZoneId': hosted_zone['HostedZoneId'],
                            'ChangeBatch': {
                                'Comment': 'Domain validation for ' + e['PhysicalResourceId'],
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

                        log_info(route53)

                time.sleep(1)

    def get_zone_for(n):
        """
        Return the hosted zone to use for validating a name

        :param str n: The name to validate
        :param props: The resource properties

        :rtype: dict

        """

        n = n.rstrip('.')
        zones = {domain['DomainName'].rstrip('.'): domain for domain in props['DomainValidationOptions']}

        parts = n.split('.')

        while len(parts):
            if '.'.join(parts) in zones:
                return zones['.'.join(parts)]

            parts = parts[1:]

        raise RuntimeError('DomainValidationOptions' + ' missing' + ' for ' + n)

    def add_tags(a):
        tags = copy.copy(e['ResourceProperties'].get('Tags', []))
        tags += [
            {'Key': 'cloudformation:' + 'logical-id', 'Value': e['LogicalResourceId']},
            {'Key': 'cloudformation:' + 'stack-id', 'Value': e['StackId']},
            {'Key': 'cloudformation:' + 'stack-name', 'Value': e['StackId'].split('/')[1]}
        ]

        acm.add_tags_to_certificate(**{'CertificateArn': a, 'Tags': tags})

    def send():
        """
        Send a response to cloudformation

        :param event: The response to send
        :type event: dict

        """

        log_info(e)
        response = requests.put(e['ResponseURL'], json=e, headers={'content-type': ''})
        log_info(response.content)
        response.raise_for_status()

    try:
        i_token = hashlib.new('md5', (e['RequestId'] + e['StackId']).encode()).hexdigest()
        props = e['ResourceProperties']

        acm = client('acm', region_name=props.get('Region'))

        e['Status'] = 'SUCCESS'

        if e['RequestType'] == 'Create':

            if e.get('Reinvoked', False) is False:
                e['PhysicalResourceId'] = 'None'
                e['PhysicalResourceId'] = request_cert()
                add_tags(e['PhysicalResourceId'])

            validate()

            if wait_for_issuance(e['PhysicalResourceId']):
                return send()
            else:
                return reinvoke()

        elif e['RequestType'] == 'Delete':

            if e['PhysicalResourceId'] != 'None':
                delete_certificate(find_certificate(e['PhysicalResourceId']))

            return send()

        elif e['RequestType'] == 'Update':

            if replace_cert():
                if e.get('Reinvoked', False) is False:
                    e['PhysicalResourceId'] = request_cert()
                    add_tags(e['PhysicalResourceId'])

                validate()

                if not wait_for_issuance(e['PhysicalResourceId']):
                    return reinvoke()
            else:
                if 'Tags' in e['Old' + 'ResourceProperties']:
                    acm.remove_tags_from_certificate(**{
                        'CertificateArn': e['PhysicalResourceId'],
                        'Tags': e['Old' + 'ResourceProperties']['Tags']
                    })

                add_tags(e['PhysicalResourceId'])

            return send()

        else:
            raise RuntimeError('Unknown RequestType')

    except Exception as ex:
        log_exception('')
        e['Status'] = 'FAILED'
        e['Reason'] = str(ex)
        return send()
