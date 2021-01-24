import os.path
from setuptools import setup, find_packages

readme_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'README.md')
with open(readme_path) as f:
    long_desc = f.read()

setup(
    name='troposphere-dns-certificate',
    description='Cloudformation DNS validated certificate resource for troposphere',
    version='1.7.3',
    author='Daniel Flook',
    author_email='daniel@flook.org',
    url='https://github.com/dflook/cloudformation-dns-certificate',
    license='MIT',
    project_urls={
        'Issues': 'https://github.com/dflook/cloudformation-dns-certificate/issues',
    },
    keywords='cloudformation troposphere certificate',
    package_dir={'': 'src'},
    packages=find_packages('src'),
    long_description=long_desc,
    long_description_content_type='text/markdown',
    install_requires=['troposphere', 'awacs', 'wrapt', 'python_minifier >= 2.3.0', 'boto3'],
    zip_safe=False
)
