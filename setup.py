# coding=utf-8
from setuptools import setup, find_packages

import os
INSTALL = ['assisted-service-client<2.28.0.post1', 'prettytable', 'PyYAML']
description = 'Assisted installer assistant'
long_description = description
if os.path.exists('README.rst'):
    long_description = open('README.rst').read()

setup(
    name='aicli',
    version='99.0',
    include_package_data=True,
    packages=find_packages(),
    zip_safe=False,
    description=description,
    long_description=long_description,
    url='http://github.com/karmab/assisted-installer-cli',
    author='Karim Boumedhel',
    author_email='karimboumedhel@gmail.com',
    license='ASL',
    install_requires=INSTALL,
    entry_points='''
        [console_scripts]
        aicli=ailib.cli:cli
    ''',
)
