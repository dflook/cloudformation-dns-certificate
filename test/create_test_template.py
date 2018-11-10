#!/usr/bin/env python3

import sys
import random
import string
from troposphere import Template, Ref, Output
import troposphere_dns_certificate.certificatemanager as certificatemanager

def create_template(zone_name, zone_id, additional_zone_name, additional_zone_id):
    template = Template(
        Description='DNS Validated ACM Certificate Test'
    )
    template.add_version()

    name = ''.join(random.choices(string.ascii_uppercase, k=5))

    template.add_resource(certificatemanager.Certificate(
        'TestCertificate',
        ValidationMethod='DNS',
        DomainName=f'{name}.{zone_name}',
        SubjectAlternativeNames=[
            f'{name}additional.{zone_name}',
            f'{name}.{additional_zone_name}'
        ],
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=zone_name,
                HostedZoneId=zone_id
            ),
            {
                'DomainName': additional_zone_name,
                'HostedZoneId': additional_zone_id
            }
        ],
        Tags=[{
            'Key': 'Name',
            'Value': 'Test Certificate'
        }]
    ))

    template.add_resource(certificatemanager.Certificate(
        'TestRegionCertificate',
        ValidationMethod='DNS',
        DomainName=f'g{name}.{zone_name}',
        SubjectAlternativeNames=[
            f'*.{zone_name}'
        ],
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName=zone_name,
                HostedZoneId=zone_id
            )
        ],
        Tags=[{
            'Key': 'Name',
            'Value': 'Test Region Certificate'
        }],
        Region='us-east-1'
    ))

    return template


if __name__ == '__main__':
    if (len(sys.argv) < 2):
        print('Usage: create_test_template.py <ZONE_NAME> <ZONE_ID> <ZONE2_NAME> <ZONE2_ID>')

    template = create_template(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    print(template.to_yaml())
