#!/usr/bin/env python

from distutils.core import setup

setup(
    name='PyJKS-wrapper',
    version='1.0',
    description='PyJKS Wrapper Library',
    author='Edgar Zamora-Gomez.',
    author_email='edgarzamoragomez@gmail.com',
    packages=['pyjks_wrapper'],
    install_requires=['pyjks==17.1.1', "pymlconf==0.8.6"]
)
