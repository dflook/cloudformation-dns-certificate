import pkgutil
import unittest

import python_minifier

LAMBDA_INLINE_CODE_LIMIT = 4096


class LambdaCodeSizeTest(unittest.TestCase):

    def test_code_below_limit(self):
        with open(pkgutil.get_loader('troposphere_dns_certificate.certificate').get_filename()) as f:
            code = python_minifier.awslambda(f.read(), entrypoint='handler')
            self.assertLess(len(code), LAMBDA_INLINE_CODE_LIMIT)
