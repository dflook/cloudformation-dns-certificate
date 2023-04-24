from template import create_stack, wait_for_stack, delete_stack, find_certificates, update_stack
from troposphere_dns_certificate import certificatemanager


def test_validation_option(hosted_zone, cross_account_hosted_zone, random_name):

    logical_id = 'TestCertificate'

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

    stack_id = create_stack('TestValidationOption', test_cert)
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

    ## Change some validation options that don't affect the certificate
    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=hosted_zone['name'],
                HostedZoneId=hosted_zone['zone_id'],
                Route53RoleArn=cross_account_hosted_zone['route53_role_arn'] + 'Wrong',
                Route53RoleExternalId='ThisWon\tBeUsed'
            )
        ],
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

    assert certificates[0]['CertificateArn'] == original_certificate['CertificateArn']

    ## cleanup
    delete_stack(stack_id)
    wait_for_stack(stack_id)
