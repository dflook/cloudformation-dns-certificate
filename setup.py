import os.path
from setuptools import setup, find_packages

readme_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'README.md')
with open(readme_path) as f:
    long_desc = f.read()

setup(
    name='troposphere-dns-certificate',
    description='Cloudformation DNS validated certificate resource for troposphere',
    author='Daniel Flook',
    author_email='daniel@flook.org',
    url='https://github.com/dflook/cloudformation-dns-certificate',
    license='MIT',
    project_urls={
        'Issues': 'https://github.com/dflook/cloudformation-dns-certificate/issues',
        'Say Thanks!': 'https://saythanks.io/to/dflook',
    },
    keywords='cloudformation troposphere certificate',
    use_scm_version=True,
    package_dir={'': 'src'},
    packages=find_packages('src'),
    long_description=long_desc,
    long_description_content_type='text/markdown',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
        'Topic :: Software Development'
    ],

    install_requires=['troposphere', 'awacs', 'wrapt', 'python_minifier'],
    zip_safe=False
)
