from template import create_stack, wait_for_stack, delete_stack, find_certificates
from troposphere_dns_certificate import certificatemanager


def test_route53_external_id(cross_account_hosted_zone, random_name):

    logical_id = 'TestCertificate'

    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{cross_account_hosted_zone["name"]}',
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=cross_account_hosted_zone['name'],
                HostedZoneId=cross_account_hosted_zone['zone_id'],
                Route53RoleArn=cross_account_hosted_zone['route53_role_arn'],
                Route53RoleExternalId=cross_account_hosted_zone['route53_external_id']
            )
        ]
    )

    stack_id = create_stack('TestRoute53RoleArn', test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1
    assert certificates[0]['KeyAlgorithm'] == 'RSA-2048'
    assert certificates[0]['DomainName'] == f'{random_name}.{cross_account_hosted_zone["name"]}'
    assert certificates[0].get('SubjectAlternativeNames', []) == [f'{random_name}.{cross_account_hosted_zone["name"]}']
    assert certificates[0]['Status'] == 'ISSUED'
    assert certificates[0]['Options']['CertificateTransparencyLoggingPreference'] == 'ENABLED'

    delete_stack(stack_id)
    wait_for_stack(stack_id)

def test_route53_missing_external_id(cross_account_hosted_zone, random_name):
    """
    Check that the role assumption is really working by doing it wrong and asserting that the stack fails.
    """

    logical_id = 'TestCertificate'

    test_cert = certificatemanager.Certificate(
        logical_id,
        ValidationMethod='DNS',
        DomainName=f'{random_name}.{cross_account_hosted_zone["name"]}',
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=cross_account_hosted_zone['name'],
                HostedZoneId=cross_account_hosted_zone['zone_id'],
                Route53RoleArn=cross_account_hosted_zone['route53_role_arn']
            )
        ]
    )

    stack_id = create_stack('TestRoute53RoleArn', test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'ROLLBACK_COMPLETE'

    delete_stack(stack_id)
    wait_for_stack(stack_id)
