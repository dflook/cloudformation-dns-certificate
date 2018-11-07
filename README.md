# Cloudformation DNS Validated Certificate Resource

The cloudformation AWS::CertificateManager::Certificate resource can only create email validated certificates.

This is a custom cloudformation resource which can additionally create DNS validated certificates for domains that use
a Route 53 hosted zone.

## Usage

It should behave identically to [AWS::CertificateManager::Certificate](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html).

The additional VerificationMethod property is supported which may be 'EMAIL' or 'DNS', as in the [API documentation](https://docs.aws.amazon.com/acm/latest/APIReference/API_RequestCertificate.html#ACM-RequestCertificate-request-ValidationMethod).

When using 'DNS' as the VerificationMethod the DomainValidation property becomes required. The DomainValidationOption
values no longer have a ValidationDomain but instead a HostedZoneId. The HostedZoneId should be the zone to create
the DNS validation records in.

Certificates may take up to 30 minutes to be issued, but typically takes ~3 minutes. The Certificate resource remains as 
CREATE_IN_PROGRESS until the certificate is issued.

To use this custom resource, copy the CustomAcmCertificateLambda and CustomAcmCertificateLambdaExecutionRole resources
into your template. You can then create certificate resources of Type: AWS::CloudFormation::CustomResource using the
properties you expect. Remember to add a ServiceToken property to the resource which references the CustomAcmCertificateLambda arn.

### Troposphere

If you are using troposphere you can install this resource as an extension using pip:

$ pip install troposphere_dns_certificate

You can then import the Certificate resource from troposphere_dns_certificate.certificatemanager instead of 
troposphere.certificatemanager. 

cloudformation.py is an example of using troposphere to create a template with a Certificate resource. 

If you are not using troposphere, you can simply copy the CustomAcmCertificateLambda and CustomAcmCertificateLambdaExecutionRole
resources from the cloudformation.json or cloudformation.yaml files.

## Examples

The certificate resource looks like:

    ExampleCertificate:
        Properties:
          DomainName: test.example.com        
          ValidationMethod: DNS
          DomainValidationOptions:
            - DomainName: test.example.com
              HostedZoneId: Z2KZ5YTUFZNC7H
          Tags:
            - Key: Name
              Value: Example Certificate
          ServiceToken: !GetAtt 'CustomAcmCertificateLambda.Arn'
        Type: AWS::CloudFormation::CustomResource

As with AWS::CertificateManager::Certificate providing the logical ID of the resource to the Ref function returns the certificate ARN.

For example (in yaml): `!Ref 'ExampleCertificate'`

### SubjectAlternativeNames

Additional names can be added to the certificate using the SubjectAlternativeNames property. A DomainValidationOptions entry should be 
present for each name. A DomainValidationOptions for a parent domain can be used for names that have the same HostedZoneId.
For example:

    ExampleCertificate:
        Properties:
          DomainName: example.com
          SubjectAlternativeNames:
            - additional.example.com
            - another.example.com    
          ValidationMethod: DNS
          DomainValidationOptions:
            - DomainName: example.com
              HostedZoneId: Z2KZ5YTUFZNC7H
          Tags:
            - Key: Name
              Value: Example Certificate
          ServiceToken: !GetAtt 'CustomAcmCertificateLambda.Arn'
    Type: AWS::CloudFormation::CustomResource

### Multiple Hosted Zones

Names from multiple hosted zones can be used by adding DomainValidationOptions for each of the hosted zones.
For example:

    ExampleCertificate:
        Properties:
          DomainName: example.com
          SubjectAlternativeNames:
            - additional.example.org
          ValidationMethod: DNS
          DomainValidationOptions:
            - DomainName: example.com
              HostedZoneId: Z2KZ5YTUFZNC7H
            - DomainName: example.org
              HostedZoneId: ZEJZ9DIN47IQN              
          Tags:
            - Key: Name
              Value: Example Certificate
          ServiceToken: !GetAtt 'CustomAcmCertificateLambda.Arn'
    Type: AWS::CloudFormation::CustomResource

### Wildcards

Wildcards can be used normally. A certificate for a name and all subdomains for example:

    ExampleCertificate:
        Properties:
          DomainName: example.com   
          SubjectAlternativeNames:
            - *.example.com               
          ValidationMethod: DNS
          DomainValidationOptions:
            - DomainName: example.com
              HostedZoneId: Z2KZ5YTUFZNC7H
          Tags:
            - Key: Name
              Value: Example Certificate
          ServiceToken: !GetAtt 'CustomAcmCertificateLambda.Arn'
        Type: AWS::CloudFormation::CustomResource
