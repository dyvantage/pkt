"""Install pkt"""

import sys
import os
from os import path
from io import open

from subprocess import call
from setuptools import setup, find_packages, Command

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

if os.getenv('CLI_BRANCH') and not None:
    cli_branch = os.getenv('CLI_BRANCH')
else:
    cli_branch="master"
    
express_cli_source = ('express-wizard @ git+file://home/tomchris/Development/express-cli#egg=express-cli')

setup(
    name = 'pkt',
    version = '0.0.1',
    description = 'deploy kubernetes on packet.net',
    long_description = long_description,
    long_description_content_type='text/markdown',
    url = 'https://github.com/dwrightco1/k8s_deploy',
    author = 'Dan Wright',
    author_email = 'dwrightco1@gmail.com',
    classifiers = [
	'Development Status :: 3 - Alpha',
	'Intended Audience :: Developers',
	'Intended Audience :: Information Technology',
        'Topic :: Software Development :: Build Tools',
	'License :: OSI Approved :: Apache Software License',
	'Programming Language :: Python :: 2',
	'Programming Language :: Python :: 2.7',
	'Programming Language :: Python :: 3',
	'Programming Language :: Python :: 3.5',
	'Programming Language :: Python :: 3.6',
    ],
    packages = find_packages(exclude = ['docs', 'tests*']),
    python_requires = '>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, <4',
    install_requires = [
        "requests",
        "urllib3",
        "prettytable",
        "argparse",
        "pprint",
        "openstacksdk>=0.12.0",
        "cryptography",
        "ConfigParser",
        "pathlib2;python_version<'3'",
        "pathlib;python_version>'3'",
        "wheel",
        ],
    extras_require = {
        'test': ['pytest', 'pytest-cov', 'mock']
    },
    entry_points = {
        'console_scripts': [
            'pkt=pkt:main',
            ],
    } 
)
