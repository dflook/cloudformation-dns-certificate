import pkgutil

import pkg_resources
import python_minifier
import troposphere.awslambda as awslambda
import troposphere.iam as iam
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal
from troposphere import AWSProperty, Tags, StackName, AccountId, Join, GetAtt
from troposphere.cloudformation import CustomResource

from troposphere_dns_certificate import TroposphereExtension

lambda_role = iam.Role(
    'CustomAcmCertificateLambdaExecutionRole',
    AssumeRolePolicyDocument=PolicyDocument(
        Version='2012-10-17',
        Statement=[
            Statement(
                Effect=Allow,
                Action=[Action('sts', 'AssumeRole')],
                Principal=Principal('Service', 'lambda.amazonaws.com')
            )
        ],
    ),
    Path="/",
    ManagedPolicyArns=[
        'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
        'arn:aws:iam::aws:policy/service-role/AWSLambdaRole'
    ],
    Policies=[iam.Policy(
        PolicyName=Join('', [StackName, 'CustomAcmCertificateLambdaExecutionPolicy']),
        PolicyDocument=PolicyDocument(
            Version='2012-10-17',
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[
                        Action('acm', 'AddTagsToCertificate'),
                        Action('acm', 'DeleteCertificate'),
                        Action('acm', 'DescribeCertificate'),
                        Action('acm', 'RemoveTagsFromCertificate'),
                        Action('acm', 'RequestCertificate')
                    ],
                    Resource=[Join('', ['arn:aws:acm:*:', AccountId, ':certificate/*'])]
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action('acm', 'RequestCertificate')
                    ],
                    Resource=['*']
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action('route53', 'ChangeResourceRecordSets')
                    ],
                    Resource=['arn:aws:route53:::hostedzone/*']
                )
            ]
        ),
    )],
)

with open(pkgutil.get_loader('troposphere_dns_certificate.certificate').get_filename()) as f:
    code = python_minifier.awslambda(f.read())

certificate_lambda = awslambda.Function(
    'CustomAcmCertificateLambda',
    Code=awslambda.Code(ZipFile=code),
    Runtime='python3.6',
    Handler='index.handler',
    Timeout=300,
    Role=GetAtt(lambda_role, 'Arn'),
    Description='Cloudformation custom resource for DNS validated certificates',
    Metadata={
        'Source': 'https://github.com/dflook/cloudformation-dns-certificate',
        'Version': pkg_resources.require('troposphere-dns-certificate')[0].version
    }
)


class DomainValidationOption(AWSProperty):
    props = {
        'DomainName': (str, True),
        'ValidationDomain': (str, False),
        'HostedZoneId': (str, False),
    }


class Certificate(CustomResource, TroposphereExtension):
    resource_type = 'Custom::DNSCertificate'

    props = {
        'DomainName': (str, True),
        'DomainValidationOptions': ([(DomainValidationOption, dict)], False),
        'SubjectAlternativeNames': ([str], False),
        'Tags': ((Tags, list), False),
        'ValidationMethod': (str, False),
        'Route53RoleArn': (str, False),
    }

    def add_extension(self, template, add_resource):
        add_helpers(template)
        return add_resource(self)

    def __init__(self, title, template=None, *args, **kwargs):
        super(Certificate, self).__init__(title, template, *args, ServiceToken=GetAtt(certificate_lambda, 'Arn'),
                                          **kwargs)


def add_helpers(template):
    """
    Add helper resources to the template

    This only needs to be called manually if for some reason the monkey patching doesn't work.

    """

    if lambda_role.title not in template.resources:
        template.add_resource(lambda_role)

    if certificate_lambda.title not in template.resources:
        template.add_resource(certificate_lambda)
