#!/usr/bin/env bash

set -e

HOSTED_ZONE_NAME=example.com
HOSTED_ZONE_ID=ABCDEFG123456
HOSTED_ZONE_ARN=arn:aws:iam::11111111111:role/Route53Role
HOSTED_ZONE2_NAME=example.org
HOSTED_ZONE2_ID=ZXCVBNM09876
HOSTED_ZONE2_ARN=arn:aws:iam::22222222222:role/Route53Role

./create_test_template.py $HOSTED_ZONE_NAME $HOSTED_ZONE_ID $HOSTED_ZONE_ARN $HOSTED_ZONE2_NAME $HOSTED_ZONE2_ID $HOSTED_ZONE2_ARN> test.yaml

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
