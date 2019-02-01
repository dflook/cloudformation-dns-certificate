import pkgutil

import pkg_resources
import python_minifier
import troposphere.awslambda as awslambda
import troposphere.iam as iam
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal
from troposphere import AWSProperty, Tags, Sub, GetAtt
from troposphere.cloudformation import CustomResource

from troposphere_dns_certificate import TroposphereExtension

CERTIFICATE_LAMBDA = 'CustomAcmCertificateLambda'
LAMBDA_ROLE = 'CustomAcmCertificateLambdaExecutionRole'


def add_helpers(template):
    """
    Add helper resources to the template

    This only needs to be called manually if for some reason the monkey patching doesn't work.

    """

    if LAMBDA_ROLE not in template.resources:
        template.add_resource(
            iam.Role(
                LAMBDA_ROLE,
                AssumeRolePolicyDocument=PolicyDocument(
                    Version='2012-10-17',
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Action=[Action('sts', 'AssumeRole')],
                            Principal=Principal('Service', 'lambda.amazonaws.com'),
                        )
                    ],
                ),
                ManagedPolicyArns=[
                    'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
                    'arn:aws:iam::aws:policy/service-role/AWSLambdaRole',
                ],
                Policies=[
                    iam.Policy(
                        PolicyName=Sub('${AWS::StackName}CustomAcmCertificateLambdaExecutionPolicy'),
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

                                    ],
                                    Resource=[Sub('arn:aws:acm:*:${AWS::AccountId}:certificate/*')],
                                ),
                                Statement(
                                    Effect=Allow,
                                    Action=[
                                        Action('acm', 'RequestCertificate'),
                                        Action('acm', 'ListTagsForCertificate'),
                                        Action('acm', 'ListCertificates')
                                    ],
                                    Resource=['*']
                                ),
                            ],
                        ),
                    )
                ],
            )
        )

    if CERTIFICATE_LAMBDA not in template.resources:
        with open(pkgutil.get_loader('troposphere_dns_certificate.certificate').get_filename()) as f:
            code = python_minifier.awslambda(f.read(), entrypoint='handler')

        template.add_resource(
            awslambda.Function(
                CERTIFICATE_LAMBDA,
                Code=awslambda.Code(ZipFile=code),
                Runtime='python3.6',
                Handler='index.handler',
                Timeout=900,
                Role=GetAtt(LAMBDA_ROLE, 'Arn'),
                Description='Cloudformation custom resource for DNS validated certificates',
                Metadata={
                    'Source': 'https://github.com/dflook/cloudformation-dns-certificate',
                    'Version': pkg_resources.require('troposphere-dns-certificate')[0].version,
                },
            )
        )


class DomainValidationOption(AWSProperty):
    props = {
        'DomainName': (str, True),
        'ValidationDomain': (str, False),
        'HostedZoneId': (str, False),
        'Route53RoleArn': (str, False),
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
        'Region': (str, False),
    }

    def add_extension(self, template, add_resource):

        add_helpers(template)

        def add_policy(policy_statement):
            policy_document = template.resources[LAMBDA_ROLE].Policies[0].PolicyDocument

            if policy_statement.properties not in [statement.properties for statement in policy_document.Statement]:
                policy_document.Statement.append(policy_statement)

        add_policy(
            Statement(
                Effect=Allow,
                Action=[Action('route53', 'ChangeResourceRecordSets')],
                Resource=['arn:aws:route53:::hostedzone/*'],
            )
        )

        role_arn = self.properties.get('Route53RoleArn', None)
        if role_arn is not None:
            add_policy(Statement(Effect=Allow, Action=[Action('sts', 'AssumeRole')], Resource=[role_arn]))

        for domain in self.properties.get('DomainValidationOptions', {}):
            if isinstance(domain, DomainValidationOption):
                role_arn = domain.properties.get('Route53RoleArn', None)
            else:
                role_arn = domain.get('Route53RoleArn', None)

            if role_arn is not None:
                add_policy(Statement(Effect=Allow, Action=[Action('sts', 'AssumeRole')], Resource=[role_arn]))

        return add_resource(self)

    def __init__(self, title, template=None, *args, **kwargs):
        super(Certificate, self).__init__(
            title, template, *args, ServiceToken=GetAtt(CERTIFICATE_LAMBDA, 'Arn'), **kwargs
        )
