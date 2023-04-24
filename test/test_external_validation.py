import time

import boto3

from template import create_stack, wait_for_stack, delete_stack, find_certificates, update_stack, describe_stack
from troposphere_dns_certificate import certificatemanager


def test_no_validation_options(hosted_zone, random_name):
    return

    logical_id = 'TestCertificate'

    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
    )

    stack_id = create_stack('TestExternalValidation', test_cert)
    time.sleep(60)
    stack = describe_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_IN_PROGRESS'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    certificate = certificates[0]

    assert certificate['KeyAlgorithm'] == 'RSA-2048'
    assert certificate['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificate.get('SubjectAlternativeNames', []) == [f'{random_name}.{hosted_zone["name"]}']
    assert certificate['Status'] == 'PENDING_VALIDATION'
    assert certificate['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    # Add the validation records ourselves
    route53 = boto3.client('route53')
    for validation_option in certificate['DomainValidationOptions']:
        assert validation_option['ValidationStatus'] == 'PENDING_VALIDATION'

        route53.change_resource_record_sets(
            HostedZoneId=hosted_zone['zone_id'],
            ChangeBatch={
                'Changes': [{
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': validation_option['ResourceRecord']['Name'],
                        'Type': validation_option['ResourceRecord']['Type'],
                        'TTL': 60,
                        'ResourceRecords': [{
                            'Value': validation_option['ResourceRecord']['Value']
                        }]
                    }
                }]
            }
        )

    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    assert certificates[0]['KeyAlgorithm'] == 'RSA-2048'
    assert certificates[0]['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificates[0].get('SubjectAlternativeNames', []) == [f'{random_name}.{hosted_zone["name"]}']
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    ## cleanup
    delete_stack(stack_id)
    wait_for_stack(stack_id)


def test_partial_validation_options(hosted_zone, cross_account_hosted_zone, random_name):

    logical_id = 'TestCertificate'

    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
        SubjectAlternativeNames=[f'{random_name}.{cross_account_hosted_zone["name"]}'],
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=hosted_zone['name'],
                HostedZoneId=hosted_zone['zone_id']
            )
        ]
    )

    stack_id = create_stack('TestExternalValidation', test_cert)
    time.sleep(60)
    stack = describe_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_IN_PROGRESS'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    certificate = certificates[0]

    assert certificate['KeyAlgorithm'] == 'RSA-2048'
    assert certificate['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificate.get('SubjectAlternativeNames', []) == [f'{random_name}.{hosted_zone["name"]}', f'{random_name}.{cross_account_hosted_zone["name"]}']
    assert certificate['Status'] == 'PENDING_VALIDATION'
    assert certificate['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    # Add the validation record ourselves
    route53 = boto3.client('route53')
    for validation_option in certificate['DomainValidationOptions']:
        if validation_option['DomainName'] != f'{random_name}.{cross_account_hosted_zone["name"]}':
            continue

        assert validation_option['ValidationStatus'] == 'PENDING_VALIDATION'

        route53.change_resource_record_sets(
            HostedZoneId=cross_account_hosted_zone['zone_id'],
            ChangeBatch={
                'Changes': [{
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': validation_option['ResourceRecord']['Name'],
                        'Type': validation_option['ResourceRecord']['Type'],
                        'TTL': 60,
                        'ResourceRecords': [{
                            'Value': validation_option['ResourceRecord']['Value']
                        }]
                    }
                }]
            }
        )

    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    assert certificates[0]['KeyAlgorithm'] == 'RSA-2048'
    assert certificates[0]['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificates[0].get('SubjectAlternativeNames', []) == [f'{random_name}.{hosted_zone["name"]}', f'{random_name}.{cross_account_hosted_zone["name"]}']
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    ## cleanup
    delete_stack(stack_id)
    wait_for_stack(stack_id)
