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
from urllib.request import Request, urlopen

logger = logging.getLogger()
logger.setLevel(logging.INFO)

log_info = logger.info
log_exception = logger.exception
shallow_copy = copy.copy
sleep = time.sleep

json_dumps = lambda j: json.dumps(j, sort_keys=True).encode()

REINVOKED = 'R'

def handler(event, context, /):
    """
    Cloudformation custom resource handler

    :param event: lambda event payload
    :param context: lambda execution context

    """

    get_remaining_time_in_millis = context.get_remaining_time_in_millis

    log_info(event)

    def request_cert():
        """
        Create a certificate

        This create an ACM certificate and update the event payload with the PhysicalResourceId.
        The certificate will not yet be issued.

        """

        api_request = shallow_copy(props)

        for key in ['ServiceToken', 'Region', 'Tags', 'Route53RoleArn']:
            api_request.pop(key, None)

        if 'ValidationMethod' in props:
            if props['ValidationMethod'] == 'DNS':

                # Check that we have all the hosted zone information we need to validate
                # before we create the certificate
                for name in set([props['DomainName']] + props.get('SubjectAlternativeNames', [])):
                    get_zone_for(name)

                del api_request['DomainValidationOptions']

        event['PhysicalResourceId'] = acm.request_certificate(
            IdempotencyToken=i_token,
            **api_request
        )['CertificateArn']
        add_tags()

    def delete_certificate(arn, /):
        """
        Delete a certificate

        Attempts to delete a certificate.

        :param str arn: Arn of the certificate to delete

        """

        while True:

            try:
                acm.delete_certificate(**{'CertificateArn': arn})
                return
            except ClientError as exception:
                log_exception('')

                err_code = exception.response['Error']['Code']

                if err_code == 'ResourceInUseException':
                    if get_remaining_time_in_millis() / 1000 < 30:
                        raise

                    sleep(5)
                    continue

                if err_code in ['ResourceNotFoundException', 'ValidationException']:
                    # If the arn is invalid, it didn't exist anyway.
                    return

                raise

            except ParamValidationError:
                # invalid arn
                return

    def find_certificate(props, /):
        """
        Find a certificate that belongs to this stack

        If the certificate is not found, returns None.

        :param dict props: The properties of the certificate to find
        :returns: The arn of the certificate
        :rtype: str or None

        """

        for page in acm.get_paginator('list_certificates').paginate():
            for certificate in page['CertificateSummaryList']:
                log_info(certificate)

                if props['DomainName'].lower() == certificate['DomainName']:
                    tags = {tag['Key']: tag['Value'] for tag in
                            acm.list_tags_for_certificate(**{'CertificateArn': certificate['CertificateArn']})['Tags']}

                    if (tags.get('cloudformation:' + 'logical-id') == event['LogicalResourceId'] and
                            tags.get('cloudformation:' + 'stack-id') == event['StackId'] and
                            tags.get('cloudformation:' + 'properties') == hash_func(props)
                    ):
                        return certificate['CertificateArn']

    def reinvoke():
        """
        Reinvoke this lambda

        The time to issue a certificate may be more than the lambda can execute for.
        This reinvokes this lambda to continue waiting.

        If this lambda has itself been reinvoked, instead raise a RuntimeError.

        """

        # Only Reinvoke once, which is a total of 30 minutes running
        if REINVOKED in event:
            raise RuntimeError('Certificate not issued in time')

        event[REINVOKED] = REINVOKED

        log_info(event)
        client('lambda').invoke(
            FunctionName=context.invoked_function_arn,
            InvocationType='Event',
            Payload=json_dumps(event)
        )

    def wait_for_issuance():
        """
        Wait until a certificate is issued

        Returns True when issued, False when lambda execution time is up.
        If the certificate fails to issue, a RuntimeError is raised

        :rtype: bool

        """

        while (get_remaining_time_in_millis() / 1000) > 30:

            cert = acm.describe_certificate(**{'CertificateArn': event['PhysicalResourceId']})['Certificate']
            log_info(cert)

            if cert['Status'] == 'ISSUED':
                return True
            elif cert['Status'] == 'FAILED':
                raise RuntimeError(cert.get('FailureReason', ''))

            sleep(5)

        return False

    def replace_cert():
        """
        Does the update require replacement of the certificate?

        Only tags can be updated without replacement

        :rtype: bool

        """

        old = shallow_copy(event['Old' + 'ResourceProperties'])
        old.pop('Tags', None)

        new = shallow_copy(event['ResourceProperties'])
        new.pop('Tags', None)

        return old != new

    def validate():
        """
        Add DNS validation records for a certificate

        """

        if props.get('ValidationMethod') != 'DNS':
            return

        while True:
            cert = acm.describe_certificate(**{'CertificateArn': event['PhysicalResourceId']})['Certificate']
            log_info(cert)

            if cert['Status'] != 'PENDING_VALIDATION':
                return

            if not [
                validation_option
                for validation_option in cert.get('DomainValidationOptions', [{}])
                if 'ValidationStatus' not in validation_option
                   or 'ResourceRecord' not in validation_option
            ]:
                # All validation options have a status and resource record to create
                break

            sleep(1)

        for validation_option in cert['DomainValidationOptions']:

            if validation_option['ValidationStatus'] == 'PENDING_VALIDATION':
                hosted_zone = get_zone_for(validation_option['DomainName'])

                role_arn = hosted_zone.get('Route53RoleArn', props.get('Route53RoleArn'))

                sts = client('sts').assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=('Certificate' + event['LogicalResourceId'])[:64],
                    DurationSeconds=900,
                )['Credentials'] if role_arn is not None else {}

                route53 = client('route53',
                     aws_access_key_id=sts.get('AccessKeyId'),
                     aws_secret_access_key=sts.get('SecretAccessKey'),
                     aws_session_token=sts.get('SessionToken'),
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

                log_info(route53)

    def get_zone_for(name, /):
        """
        Return the hosted zone to use for validating a name

        :param str name: The name to validate
        :rtype: dict

        """

        name = name.rstrip('.')
        zones = {domain['DomainName'].rstrip('.'): domain for domain in props['DomainValidationOptions']}

        parts = name.split('.')

        while len(parts):
            if '.'.join(parts) in zones:
                return zones['.'.join(parts)]

            parts = parts[1:]

        raise RuntimeError('DomainValidationOptions' + ' missing for ' + name)

    hash_func = lambda v: hashlib.new('md5', json_dumps(v)).hexdigest()

    def add_tags():
        """
        Add tags from the ResourceProperties to the Certificate

        Also adds logical-id, stack-id, stack-name and properties tags, which are used by the custom resource.

        """

        tags = shallow_copy(event['ResourceProperties'].get('Tags', []))
        tags += [
            {'Key': 'cloudformation:' + 'logical-id', 'Value': event['LogicalResourceId']},
            {'Key': 'cloudformation:' + 'stack-id', 'Value': event['StackId']},
            {'Key': 'cloudformation:' + 'stack-name', 'Value': event['StackId'].split('/')[1]},
            {'Key': 'cloudformation:' + 'properties', 'Value': hash_func(event['ResourceProperties'])}
        ]

        acm.add_tags_to_certificate(**{'CertificateArn': event['PhysicalResourceId'], 'Tags': tags})

    def send_response():
        """
        Send a response to cloudformation

        """

        log_info(event)

        response = urlopen(Request(event['ResponseURL'], json_dumps(event), {'content-type': ''}, method='PUT'))

        if response.status != 200:
            raise Exception(response)

    try:
        i_token = hash_func(event['RequestId'] + event['StackId'])
        props = event['ResourceProperties']

        acm = client('acm', region_name=props.get('Region'))

        event['Status'] = 'SUCCESS'

        if event['RequestType'] == 'Create':

            if REINVOKED not in event:
                event['PhysicalResourceId'] = 'None'
                request_cert()

            validate()

            if not wait_for_issuance():
                return reinvoke()

        elif event['RequestType'] == 'Delete':

            if event['PhysicalResourceId'] != 'None':
                if event['PhysicalResourceId'].startswith('arn:'):
                    delete_certificate(event['PhysicalResourceId'])
                else:
                    delete_certificate(find_certificate(props))

        elif event['RequestType'] == 'Update':

            if replace_cert():
                log_info('Update')

                if find_certificate(props) == event['PhysicalResourceId']:
                    # This is an update cancel request.

                    # Try and delete the new certificate that is no longer required
                    try:
                        acm = client('acm', region_name=event['OldResourceProperties'].get('Region'))
                        log_info('Delete')
                        delete_certificate(find_certificate(event['OldResourceProperties']))
                    except:
                        log_exception('')

                    # return success for the update - nothing changed
                    return send_response()

                if REINVOKED not in event:
                    request_cert()

                validate()

                if not wait_for_issuance():
                    return reinvoke()
            else:
                if 'Tags' in event['Old' + 'ResourceProperties']:
                    acm.remove_tags_from_certificate(**{
                        'CertificateArn': event['PhysicalResourceId'],
                        'Tags': event['Old' + 'ResourceProperties']['Tags']
                    })

                add_tags()

        else:
            raise RuntimeError(event['RequestType'])

        return send_response()

    except Exception as ex:
        log_exception('')
        event['Status'] = 'FAILED'
        event['Reason'] = str(ex)
        return send_response()
