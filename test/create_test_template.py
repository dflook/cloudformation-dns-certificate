#!/usr/bin/env python3

import sys
import random
import string
from troposphere import Template, Ref, Output
import troposphere_dns_certificate.certificatemanager as certificatemanager


def create_template(zone_name, zone_id, zone_arn, additional_zone_name, additional_zone_id, additional_zone_arn):
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
                HostedZoneId=zone_id,
                Route53RoleArn=zone_arn
            ),
            {
                'DomainName': additional_zone_name,
                'HostedZoneId': additional_zone_id,
                'Route53RoleArn': additional_zone_arn
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
        Route53RoleArn=zone_arn,
        Tags=[{
            'Key': 'Name',
            'Value': 'Test Region Certificate'
        }],
        Region='eu-west-3'
    ))

    return template


if __name__ == '__main__':
    if (len(sys.argv) < 6):
        print('Usage: create_test_template.py <ZONE_NAME> <ZONE_ID> <ZONE_ARN> <ZONE2_NAME> <ZONE2_ID> <ZONE2_ARN>')

    template = create_template(sys.argv[1],
                               sys.argv[2],
                               sys.argv[3],
                               sys.argv[4],
                               sys.argv[5],
                               sys.argv[6])
    print(template.to_yaml())
