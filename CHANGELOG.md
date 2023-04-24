# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2023-04-24

:warning: This version requires an additional `acm:UpdateCertificateOptions` permission to be added to the Lambda execution role.
Ensure your `CustomAcmCertificateLambdaExecutionRole` is up to date with the example in `cloudformation.[yaml|json]`.

### Added
Missing certificate property compared to `AWS::CertificateManager::Certificate`:

- `CertificateTransparencyLoggingPreference` has been added to control certificate transparency logging.

New enhancements over `AWS::CertificateManager::Certificate`:

- A new `KeyAlgorithm` certificate property has been added to specify the key algorithm to use.
  The default is `RSA_2048`, which is the same as `AWS::CertificateManager::Certificate`. Not all algorithms are supported by all clients, AWS Services or regions.

### Changed
- A DomainValidationOption is no longer required for all domains in the certificate. If a DomainValidationOption is not specified for a domain, no validation record will be created for that domain.
  The validation records will need to be created through some other means. The certificate resource will be in the `CREATE_IN_PROGRESS` state until the validation records are created.

- The certificate resource will not necessarily be replaced on changes to the `DomainValidationOptions` property. 
  Only changes to `DomainName` or `HostedZoneId` in `DomainValidationOptions` will cause the certificate to be replaced.

### Fixed
- Failures that could occur when creating or updating large numbers of certificates in parallel.

## [1.8.0] - 2023-04-23

### Added
- A new optional `Route53RoleExternalId` domain validation option. This specifies an ExternalId to use when assuming the `Route53RoleArn`. Thanks [pritamrungta](https://github.com/pritamrungta)!

## [1.7.5] - 2023-02-06

### Fixed
- Resolve cfn-lint check I3042 about hardcoded partition in arn. Thanks [CurryEleison](https://github.com/CurryEleison)!

## [1.7.4] - 2022-05-19

### Changed
- Updated lambda runtime to Python 3.9. AWS Lambda support for Python 3.6 is coming to an end.

## [1.7.3] - 2021-01-24

### Fixed
- Avoid unnecessary requests when updating/deleting certificate that could result in a ThrottlingException - thanks @danieljamesscott

## [1.7.2] - 2019-11-18

### Fixed
- No longer use undocumented vendored requests library from boto3

## [1.7.1] - 2019-08-06

### Fixed
- Certificate creation failing in some regions after a change in ACM API behaviour

## [1.7.0] - 2019-02-15

### Added
- Support for cancelling certificate update. This can occur when a stack update is cancelled, perhaps due to another
  resource failing to create/update/delete

## [1.6.0] - 2019-02-01

### Added
- The requested certificate is automatically tagged with `cloudformation:logical-id`, `cloudformation:stack-id` and `cloudformation:stack-name`
- Support for cancelling certificate creation. This can occur when a rollback is triggered while a certificate is creating

## [1.5.1] - 2019-01-31

### Fixed
- Cloudformation resource failing to delete when the certificate was deleted

## [1.5.0] - 2019-01-26
### Added
- `Route53RoleArn` is now a property of DomainValidationOption, allowing a different role per hosted zone
- `Route53RoleArn` can be specified using troposphere, which automatically modifies the execution policy

### Changed
- Lambda runtime increased to 15 minutes, with total issuance timeout decreased to 30 minutes

### Fixed
- Will no longer occasionally create multiple certificates when issuance took over 5 minutes
- Deletion is more robust and will be retried for up to 15 minutes if certificate is in use

## [1.4.0] - 2018-11-30
### Added
- `Route53RoleArn` property for creating certificates for hosted zones in other accounts - Thanks pitkley

## [1.3.0] - 2018-10-10
### Added
- `Region` property for creating certificates in other regions

## [1.2.1] - 2018-10-07
### Fixed
- `SignatureDoesNotMatch` error in some regions - Thanks mseiwald

## [1.2.0] - 2018-06-13
### Fixed
- Allow using a parent domain for the HostedZoneId 

## [1.1.0] - 2018-05-28
### Changed
- Better handle issuance failure

## [1.0.0] - 2018-05-26
### Added
- First release

[2.0.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.8.0...2.0.0
[1.8.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.7.5...1.8.0
[1.7.5]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.7.4...1.7.5
[1.7.4]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.7.3...1.7.4
[1.7.3]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.7.2...1.7.3
[1.7.2]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.7.1...1.7.2
[1.7.1]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.7.0...1.7.1
[1.7.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.6.0...1.7.0
[1.6.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.5.1...1.6.0
[1.5.1]: https://github.com/dflook/cloudformation-dns-certificate/compare/1.5.0...1.5.1
[1.5.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/a64051e43ae8696c898b6634fbe663abc4a87785...1.5.0
[1.4.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/d0884b638cb2e7873aa7b7f9fda2a1bf377d8892...a64051e43ae8696c898b6634fbe663abc4a87785
[1.3.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/91ef66d068be9fbc97882ae8c6bf51e0d875f9fd...d0884b638cb2e7873aa7b7f9fda2a1bf377d8892
[1.2.1]: https://github.com/dflook/cloudformation-dns-certificate/compare/3571b4d09435608913857a521aa8d1acbf031d55...91ef66d068be9fbc97882ae8c6bf51e0d875f9fd
[1.2.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/aaa0d29fd7ece40904e1b1e6add88a12a2dbe6bc...3571b4d09435608913857a521aa8d1acbf031d55
[1.1.0]: https://github.com/dflook/cloudformation-dns-certificate/compare/360a41fb3910fd1ec58f466be4ee8f36bc7ccbb9...aaa0d29fd7ece40904e1b1e6add88a12a2dbe6bc
[1.0.0]: https://github.com/dflook/cloudformation-dns-certificate/commit/c393fe6f86dd2ce3601ec56422d200441ae0f576
