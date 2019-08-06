from troposphere import Template, Ref, Output

import troposphere_dns_certificate.certificatemanager as certificatemanager


def create_template():
    template = Template(
        Description='DNS Validated ACM Certificate Example'
    )
    template.set_version()

    certificate = template.add_resource(certificatemanager.Certificate(
        'ExampleCertificate',
        ValidationMethod='DNS',
        DomainName='test.example.com',
        DomainValidationOptions=[
            certificatemanager.DomainValidationOption(
                DomainName='test.example.com',
                HostedZoneId='Z2KZ5YTUFZNC7H'
            )
        ],
        Tags=[{
            'Key': 'Name',
            'Value': 'Example Certificate'
        }]
    ))

    template.add_output(Output(
        'CertificateARN',
        Value=Ref(certificate),
        Description='The ARN of the example certificate'
    ))

    return template


if __name__ == '__main__':
    template = create_template()

    with open('cloudformation.yaml', 'w') as f:
        f.write(template.to_yaml())

    with open('cloudformation.json', 'w') as f:
        f.write(template.to_json())
