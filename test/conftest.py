import string
import random

import pytest


@pytest.fixture()
def random_name():
    """Generate a random name"""
    return ''.join(random.choices(string.ascii_lowercase, k=5))

@pytest.fixture()
def hosted_zone():
    """A hosted zone we can use for testing"""
    return {
        "name": "cdc.example.com",
        "zone_id": "AAAAAAAAAAAAAAAAAAAA"
    }

@pytest.fixture()
def cross_account_hosted_zone():
    """A hosted zone we need to assume a role to use"""
    return {
        "name": "cdc-2.example.com",
        "route53_external_id": "secret",
        "route53_role_arn": "arn:aws:iam::1111111111111:role/additional_test_zone_role",
        "zone_id": "BBBBBBBBBBBBBBBBBB"
    }
