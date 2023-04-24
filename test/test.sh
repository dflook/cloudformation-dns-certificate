#!/usr/bin/env bash

set -e

HOSTED_ZONE_NAME=cdc.example.com
HOSTED_ZONE_ID=AAAAAAAAAAAAAAAAAAAA
HOSTED_ZONE_ARN=arn:aws:iam::11111111111:role/test_zone_role
HOSTED_ZONE2_NAME=cdc-2.example.com
HOSTED_ZONE2_ID=BBBBBBBBBBBBBBBBBB
HOSTED_ZONE2_ARN=arn:aws:iam::22222222222:role/additional_test_zone_role
HOSTED_ZONE2_EXTERNAL_ID=abcdefgh

./create_test_template.py $HOSTED_ZONE_NAME $HOSTED_ZONE_ID $HOSTED_ZONE_ARN $HOSTED_ZONE2_NAME $HOSTED_ZONE2_ID $HOSTED_ZONE2_ARN $HOSTED_ZONE2_EXTERNAL_ID> test.yaml

for region in $(aws ec2 describe-regions --query "Regions[].{Name:RegionName}" --output text)
do
    export AWS_DEFAULT_REGION=$region
    echo "Testing in $region"

    if ! aws cloudformation deploy --template-file test.yaml --stack-name dns-cert-test --capabilities CAPABILITY_NAMED_IAM; then
        echo "Failed to create in $region"
        echo "Run 'aws cloudformation delete-stack --stack-name dns-cert-test' to cleanup"
        exit 1
    fi

    echo "Success in $region"
    aws cloudformation delete-stack --stack-name dns-cert-test

    echo "sleeping"
    sleep 30
done

echo "Success in all regions"
