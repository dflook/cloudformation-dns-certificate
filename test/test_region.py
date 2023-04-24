from template import create_stack, wait_for_stack, delete_stack, find_certificates, update_stack
from troposphere_dns_certificate import certificatemanager


def test_cross_region(hosted_zone, random_name):
    """Test that a certificate can be created in a different region than the stack."""

    logical_id = 'TestCertificate'

    ## Create certificate in a different region
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
        Region='us-east-1'
    )

    stack_id = create_stack('TestCrossRegion', test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id, 'us-east-1'))
    assert len(certificates) == 1
    assert certificates[0]['KeyAlgorithm'] == 'RSA-2048'
    assert certificates[0]['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificates[0].get('SubjectAlternativeNames', []) == [f'{random_name}.{hosted_zone["name"]}']
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    assert list(find_certificates(stack_id, logical_id)) == []

    original_certificate = certificates[0]

    ## Recreate certificate in the current region
    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=hosted_zone['name'],
                HostedZoneId=hosted_zone['zone_id']
            )
        ]
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

    assert list(find_certificates(stack_id, logical_id, 'us-east-1')) == []

    assert certificates[0]['CertificateArn'] != original_certificate['CertificateArn']

    delete_stack(stack_id)
    wait_for_stack(stack_id)
