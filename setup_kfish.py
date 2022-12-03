# coding=utf-8
from setuptools import setup

description = 'Redfish helper library'
long_description = description
setup(
    name='kfish',
    version='99.0',
    include_package_data=False,
    packages=['kfish'],
    zip_safe=False,
    description=description,
    long_description=long_description,
    url='https://github.com/karmab/aicli/blob/main/kfish.md',
    author='Karim Boumedhel',
    author_email='karimboumedhel@gmail.com',
    license='ASL',
)
