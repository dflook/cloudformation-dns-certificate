from template import create_stack, wait_for_stack, delete_stack, find_certificates, update_stack
from troposphere_dns_certificate import certificatemanager


def test_ct_logging(hosted_zone, random_name):

    logical_id = 'TestCertificate'

    ## Create initial certificate with default enabled
    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=hosted_zone['name'],
                HostedZoneId=hosted_zone['zone_id']
            )
        ],
    )

    stack_id = create_stack('TestCTLogging', test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    assert certificates[0]['KeyAlgorithm'] == 'RSA-2048'
    assert certificates[0]['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificates[0].get('SubjectAlternativeNames', []) == [f'{random_name}.{hosted_zone["name"]}']
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    original_certificate = certificates[0]

    ## Explicitly enable CT logging
    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=hosted_zone['name'],
                HostedZoneId=hosted_zone['zone_id']
            )
        ],
        CertificateTransparencyLoggingPreference='ENABLED'
    )

    stack_id = update_stack(stack_id, test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'UPDATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    assert certificates[0]['KeyAlgorithm'] == 'RSA-2048'
    assert certificates[0]['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificates[0].get('SubjectAlternativeNames', []) == [f'{random_name}.{hosted_zone["name"]}']
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    # Check the certificate was not replaced
    assert certificates[0]['CertificateArn'] == original_certificate['CertificateArn']

    ## Explicitly disable CT logging
    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=hosted_zone['name'],
                HostedZoneId=hosted_zone['zone_id']
            )
        ],
        CertificateTransparencyLoggingPreference='DISABLED'
    )

    stack_id = update_stack(stack_id, test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'UPDATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    assert certificates[0]['KeyAlgorithm'] == 'RSA-2048'
    assert certificates[0]['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificates[0].get('SubjectAlternativeNames', []) == [f'{random_name}.{hosted_zone["name"]}']
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'DISABLED'

    # Check the certificate was not replaced
    assert certificates[0]['CertificateArn'] == original_certificate['CertificateArn']

    # Cleanup
    delete_stack(stack_id)
    wait_for_stack(stack_id)
