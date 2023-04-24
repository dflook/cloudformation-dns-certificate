import time
from typing import Any, Iterable

import boto3

from troposphere import Template
from troposphere_dns_certificate import certificatemanager

cloudformation = boto3.client('cloudformation')
acm = boto3.client('acm')

def describe_stack(stack_id: str) -> dict[str, Any]:
    response = cloudformation.describe_stacks(StackName=stack_id)
    return response['Stacks'][0]

def wait_for_stack(stack_id: str) -> dict[str, Any]:
    """
    Wait for a stack operation to reach a terminal state.
    """

    while True:
        response = cloudformation.describe_stacks(StackName=stack_id)
        stack = response['Stacks'][0]
        if stack['StackStatus'].endswith('_COMPLETE') or stack['StackStatus'].endswith('_FAILED'):
            break

        time.sleep(5)

    return stack

def create_stack(stack_name: str, certificate: certificatemanager.Certificate) -> str:
    template = Template(
        Description='cloudformation-dns-certificate Test Stack'
    )
    template.set_version()
    template.add_resource(certificate)

    response = cloudformation.create_stack(
        StackName=stack_name,
        TemplateBody=template.to_json(),
        Capabilities=['CAPABILITY_NAMED_IAM'],
        TimeoutInMinutes=5
    )

    return response['StackId']

def update_stack(stack_id: str, certificate: certificatemanager.Certificate) -> str:
    template = Template(
        Description='cloudformation-dns-certificate Test Stack'
    )
    template.set_version()
    template.add_resource(certificate)

    response = cloudformation.update_stack(
        StackName=stack_id,
        TemplateBody=template.to_json(),
        Capabilities=['CAPABILITY_NAMED_IAM'],
    )

    return response['StackId']


def delete_stack(stack_id: str) -> None:
    cloudformation.delete_stack(StackName=stack_id)

def find_certificates(stack_id: str, logical_id: str, region_name: str=None) -> Iterable[dict[str, Any]]:

    acm = boto3.client('acm', region_name=region_name)

    for page in acm.get_paginator('list_certificates').paginate():
        for cert_summary in page['CertificateSummaryList']:

                tags = {tag['Key']: tag['Value'] for tag in
                        acm.list_tags_for_certificate(**{'CertificateArn': cert_summary['CertificateArn']})['Tags']}

                if (tags.get('cloudformation:logical-id') == logical_id
                    and tags.get('cloudformation:stack-id') == stack_id
                ):
                    cert = acm.describe_certificate(CertificateArn=cert_summary['CertificateArn'])['Certificate']
                    cert['Tags'] = tags
                    yield cert
