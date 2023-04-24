from template import create_stack, wait_for_stack, delete_stack, find_certificates, update_stack
from troposphere_dns_certificate import certificatemanager

def test_tags(hosted_zone, random_name):

    logical_id = 'TestCertificate'

    ## Create initial certificate with no tags
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

    stack_id = create_stack('TestTags', test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'CREATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1

    tags = certificates[0]['Tags']
    assert len(tags.keys()) == 4
    assert tags['cloudformation:logical-id'] == logical_id
    assert tags['cloudformation:stack-id'] == stack_id
    assert tags['cloudformation:stack-name'] == 'TestTags'
    assert 'cloudformation:properties' in tags

    original_certificate = certificates[0]

    ## Update the certificate by adding a tag
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
        Tags=[{
            'Key': 'Name',
            'Value': 'Test Certificate'
        }]
    )

    stack_id = update_stack(stack_id, test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'UPDATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1

    tags = certificates[0]['Tags']
    assert len(tags.keys()) == 5
    assert tags['cloudformation:logical-id'] == logical_id
    assert tags['cloudformation:stack-id'] == stack_id
    assert tags['cloudformation:stack-name'] == 'TestTags'
    assert 'cloudformation:properties' in tags
    assert tags['Name'] == 'Test Certificate'

    # Check the certificate was not replaced
    assert certificates[0]['CertificateArn'] == original_certificate['CertificateArn']

    ## Update the certificate by removing a tag and adding a different one
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
        Tags=[{
            'Key': 'Hello',
            'Value': 'World'
        }]
    )

    stack_id = update_stack(stack_id, test_cert)
    stack = wait_for_stack(stack_id)
    assert stack['StackStatus'] == 'UPDATE_COMPLETE'

    certificates = list(find_certificates(stack_id, logical_id))
    assert len(certificates) == 1

    tags = certificates[0]['Tags']
    assert len(tags.keys()) == 5
    assert tags['cloudformation:logical-id'] == logical_id
    assert tags['cloudformation:stack-id'] == stack_id
    assert tags['cloudformation:stack-name'] == 'TestTags'
    assert 'cloudformation:properties' in tags
    assert tags['Hello'] == 'World'

    # Check the certificate was not replaced
    assert certificates[0]['CertificateArn'] == original_certificate['CertificateArn']

    ## cleanup
    delete_stack(stack_id)
    wait_for_stack(stack_id)
