# Cloudformation DNS Validated Certificate Resource

This is a cloudformation custom resource which is an enhancement of the [AWS::CertificateManager::Certificate](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html) resource.

It allows creating a certificate in a region different from the stack's region (e.g. `us-east-1` for cloudfront),
and allows for creating a certificate for a Route 53 hosted zone in another AWS account.

## Usage

To use this custom resource, copy the CustomAcmCertificateLambda and CustomAcmCertificateLambdaExecutionRole resources
into your template. You can then create certificate resources of Type: `Custom::DNSCertificate`.

This resource is also available as troposphere extension, in the [troposphere-dns-certificate](https://pypi.org/project/troposphere-dns-certificate/) package

Remember to add a ServiceToken property to the resource which references the CustomAcmCertificateLambda arn.
Certificates may take up to 30 minutes to be issued, but typically takes ~3 minutes. The Certificate resource remains as 
CREATE_IN_PROGRESS until the certificate is issued.

### Differences from AWS::CertificateManager::Certificate
It should behave similarly to [AWS::CertificateManager::Certificate](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html), 
except for the differences described here.

The additional `Region` property can be used to set the region to create the certificate in.

The [DomainValidationOption](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-certificatemanager-certificate-domainvalidationoption.html) has an additional property `Route53RoleArn`, which is a role to assume before creating DNS validation records.
This lets you create a certificate for a hosted zone in another account.

### Certificate Resource

#### Syntax

```yaml
Type: Custom::DNSCertificate
Properties: 
  DomainName: String
  DomainValidationOptions:
    - DomainValidationOption
  SubjectAlternativeNames:
    - String
  Tags:
    - Resource Tag
  ValidationMethod: String
  Region: String
  ServiceToken: !GetAtt 'CustomAcmCertificateLambda.Arn'  
```

#### Properties

* `DomainName`

  Fully qualified domain name (FQDN) to issue the certificate for. Use an asterisk as a wildcard.

  - Required: Yes
  - Type: String
  - Update requires: [Replacement](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement)
  
* `DomainValidationOptions`

  Information for validating domain ownership. A DomainValidationOption should be present for the DomainName and all 
  SubjectAlternativeNames. A DomainValidationOption for a parent domain can be used for names that have the same HostedZoneId.

  - Required: Yes
  - Type: List of `DomainValidationOption`
  - Update requires: [Replacement](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement)  

* `SubjectAlternativeNames`

  FQDNs to include in the Subject Alternative Name of the certificate.

  - Required: No
  - Type: List of String values
  - Update requires: [Replacement](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement)  

* `Tags`

  Tags for this certificate

  - Required: No
  - Type: [Resource Tag](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html)
  - Update requires: [No interruption](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-no-interrupt)  

* `ValidationMethod`

  Method to use to validate domain ownership. This should be `DNS`.

  - Required: No
  - Default: `EMAIL`
  - Type: String
  - Update requires: [Replacement](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement) 

* `Region`

  The region to create the certificate in.

  - Required: No
  - Default: The Stack's region
  - Type: String
  - Update requires: [Replacement](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement) 

#### Return value

* Ref

  When the [`Ref`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html) 
  function is used on the logical ID of a Certificate resource the certificate ARN is returned.

### DomainValidationOption

#### Syntax

```yaml
DomainName: String
HostedZoneId: String
Route53RoleArn: String
```

#### Properties

* `DomainName`

  Fully qualified domain name of the validation request.

  - Required: Yes
  - Type: String
  
* `HostedZoneId`

  The Route53 Hosted Zone to create validation records in.

  - Required: Yes
  - Type: String
  
* `Route53RoleArn`

  The arn of an IAM Role to assume when creating DNS validation records. This can be used to create the records for a
  Hosted Zone in another AWS account.

  - Required: No
  - Type: String
 
## Troposphere

If you are using troposphere you can install this resource as an extension using pip:

    $ pip install troposphere_dns_certificate

You can then import the Certificate resource from troposphere_dns_certificate.certificatemanager instead of troposphere.certificatemanager. 

cloudformation.py is an example of using troposphere to create a template with a Certificate resource. 

If you are not using troposphere, you can simply copy the CustomAcmCertificateLambda and CustomAcmCertificateLambdaExecutionRole
resources from the cloudformation.json or cloudformation.yaml files.

## Examples

The certificate resource looks like:

```yaml
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
  Type: Custom::DNSCertificate
```


As with AWS::CertificateManager::Certificate providing the logical ID of the resource to the Ref function returns the certificate ARN.

For example (in yaml): `!Ref 'ExampleCertificate'`

### SubjectAlternativeNames

Additional names can be added to the certificate using the SubjectAlternativeNames property.

```yaml
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
Type: Custom::DNSCertificate
```

### Multiple Hosted Zones

Names from multiple hosted zones can be used by adding DomainValidationOptions for each of the hosted zones.
For example:

```yaml
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
Type: Custom::DNSCertificate
```

### Wildcards

Wildcards can be used normally. A certificate for a name and all subdomains for example:

```yaml
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
  Type: Custom::DNSCertificate
```

### Specifying a region

This example uses the Region property to create the certificate in us-east-1, for use with cloudfront:

```yaml
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
  Type: Custom::DNSCertificate
```

### Assuming a role for Route 53 record creation

In some cases the account owning the hosted zone might be a different one than the one you are generating the certificate in.
To support this you can specify the domain validation option property `Route53RoleArn` with a role-ARN that should be 
assumed before creating the records required for certificate validation.

If a top-level Route53RoleArn property is specified it will be assumed when validating domains that don't contain a
Route53RoleArn domain validation option property.

```yaml
ExampleCertificate:
  Properties:
    DomainName: test.example.com
    ValidationMethod: DNS
    DomainValidationOptions:
      - DomainName: test.example.com
        HostedZoneId: Z2KZ5YTUFZNC7H
        Route53RoleArn: arn:aws:iam::TRUSTING-ACCOUNT-ID:role/ACMRecordCreationRole
    Tags:
      - Key: Name
        Value: Example Certificate
    ServiceToken: !GetAtt 'CustomAcmCertificateLambda.Arn'
  Type: Custom::DNSCertificate
```

Additionally you have to allow the assumption of this role by adding this statement to the CustomAcmCertificateLambdaExecutionRole:

```yaml
- Action:
    - sts:AssumeRole
  Resource:
    - arn:aws:iam::TRUSTING-ACCOUNT-ID:role/ACMRecordCreationRole
  Effect: Allow
```

If you are using the troposphere extension, this statement is added automatically. The full CustomAcmCertificateLambdaExecutionRole
for this example would look like:

```yaml
CustomAcmCertificateLambdaExecutionRole:
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Action:
            - sts:AssumeRole
          Effect: Allow
          Principal:
            Service: lambda.amazonaws.com
      Version: '2012-10-17'
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      - arn:aws:iam::aws:policy/service-role/AWSLambdaRole
    Policies:
      - PolicyDocument:
          Statement:
            - Action:
                - acm:AddTagsToCertificate
                - acm:DeleteCertificate
                - acm:DescribeCertificate
                - acm:RemoveTagsFromCertificate
              Effect: Allow
              Resource:
                - !Sub 'arn:aws:acm:*:${AWS::AccountId}:certificate/*'
            - Action:
                - acm:RequestCertificate
                - acm:ListTagsForCertificate
                - acm:ListCertificates
              Effect: Allow
              Resource:
                - '*'
            - Action:
                - route53:ChangeResourceRecordSets
              Effect: Allow
              Resource:
                - arn:aws:route53:::hostedzone/*
            - Action:
                - sts:AssumeRole
              Effect: Allow
              Resource:
                - arn:aws:iam::TRUSTING-ACCOUNT-ID:role/ACMRecordCreationRole
          Version: '2012-10-17'
        PolicyName: !Sub '${AWS::StackName}CustomAcmCertificateLambdaExecutionPolicy'
```

The IAM role in the account with the hosted zone would look something like:

```yaml
ACMRecordCreationRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Action:
            - sts:AssumeRole
          Principal:
            AWS:
              - arn:aws:iam::TRUSTED-ACCOUNT-ID:root
          Effect: Allow
      Version: '2012-10-17'
    Policies:
      - PolicyName: 'ACMRecordCreation'
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
            - Action:
                - route53:ChangeResourceRecordSets
              Resource:
                - arn:aws:route53:::hostedzone/Z2KZ5YTUFZNC7H
              Effect: Allow
    RoleName: ACMRecordCreationRole
```
