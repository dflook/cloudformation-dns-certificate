from template import create_stack, wait_for_stack, delete_stack, find_certificates, update_stack
from troposphere_dns_certificate import certificatemanager


def test_replace(hosted_zone, cross_account_hosted_zone, random_name):

    logical_id = 'TestCertificate'

    ## Create initial certificate with one san
    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
        SubjectAlternativeNames=[f'{random_name}-2.{hosted_zone["name"]}'],
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=hosted_zone['name'],
                HostedZoneId=hosted_zone['zone_id']
            )
        ]
    )

    stack_id = create_stack('TestDomainReplace', test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    assert certificates[0]['KeyAlgorithm'] == 'RSA-2048'
    assert certificates[0]['DomainName'] == f'{random_name}.{hosted_zone["name"]}'
    assert certificates[0].get('SubjectAlternativeNames', []) == [
        f'{random_name}.{hosted_zone["name"]}',
        f'{random_name}-2.{hosted_zone["name"]}'
    ]
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    original_certificate = certificates[0]

    ## Move the SAN to another hosted zone
    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{hosted_zone["name"]}',
        SubjectAlternativeNames=[f'{random_name}.{cross_account_hosted_zone["name"]}'],
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=hosted_zone['name'],
                HostedZoneId=hosted_zone['zone_id']
            ),
            certificatemanager.DomainValidationOption(
                DomainName=cross_account_hosted_zone['name'],
                HostedZoneId=cross_account_hosted_zone['zone_id'],
                Route53RoleArn=cross_account_hosted_zone['route53_role_arn'],
                Route53RoleExternalId=cross_account_hosted_zone['route53_external_id']
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
    assert certificates[0].get('SubjectAlternativeNames', []) == [
        f'{random_name}.{hosted_zone["name"]}',
        f'{random_name}.{cross_account_hosted_zone["name"]}'
    ]
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    assert certificates[0]['CertificateArn'] != original_certificate['CertificateArn']

    ## cleanup
    delete_stack(stack_id)
    wait_for_stack(stack_id)
