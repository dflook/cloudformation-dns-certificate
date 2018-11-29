# Cloudformation DNS Validated Certificate Resource

The cloudformation AWS::CertificateManager::Certificate resource can only create email validated certificates.

This is a custom cloudformation resource which can additionally create DNS validated certificates for domains that use
a Route 53 hosted zone. It can also create certificates in a region other than the stack's region.

## Usage

It should behave identically to [AWS::CertificateManager::Certificate](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html), 
except for the differences described here.

When using 'DNS' as the ValidationMethod the DomainValidation property becomes required, and the DomainValidationOption
requires a HostedZoneId instead of a ValidationDomain. The HostedZoneId should be the zone to create the DNS validation 
records in.

The additional 'Region' property can be used to set the region to create the certificate in.

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

### Specifying a region

This example uses the Region property to create the certificate in us-east-1, for use with cloudfront:

    ExampleCertificate:
        Properties:
          DomainName: example.com          
          ValidationMethod: DNS
          DomainValidationOptions:
            - DomainName: example.com
              HostedZoneId: Z2KZ5YTUFZNC7H
          Region: us-east-1
          Tags:
            - Key: Name
              Value: Example Certificate
          ServiceToken: !GetAtt 'CustomAcmCertificateLambda.Arn'
        Type: AWS::CloudFormation::CustomResource

### Assuming a role for Route 53 record creation

In some cases the account owning the hosted zone might be a different one than the one you are generating the certificate in.
To support this you can specify the top-level property `AssumeRole` with a role-ARN that should be assumed before creating the records required for certificate validation.

    ExampleCertificate:
        Properties:
          DomainName: test.example.com
          ValidationMethod: DNS
          DomainValidationOptions:
            - DomainName: test.example.com
              HostedZoneId: Z2KZ5YTUFZNC7H
          AssumeRole: arn:aws:iam::123412341234:role/RoleAllowedToEditHostedZone
          Tags:
            - Key: Name
              Value: Example Certificate
          ServiceToken: !GetAtt 'CustomAcmCertificateLambda.Arn'
        Type: AWS::CloudFormation::CustomResource

Additionally you have to allow the assumption of this role through the execution role, e.g.:

    CustomAcmCertificateLambdaExecutionRole:
      Properties:
        ...
        Policies:
          - PolicyDocument:
              Statement:
                ...
                - Action:
                    - sts:AssumeRole
                  Effect: Allow
                  Resource:
                    - arn:aws:iam::123412341234:role/RoleAllowedToEditHostedZone

Note:

* This property is only used if you use `ValidationMethod: DNS`.
* It is currently not supported to assume different roles for different hosted zones.
