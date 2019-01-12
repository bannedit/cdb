#!/usr/bin/env python
# encoding: utf-8

import os, sys
from setuptools import setup

setup(
    name = 'cdb',
    description='cdb is a Python 3 wrapper for Windows Debugging Tools debugger cdb.exe.',
    long_description="""
cdb is a Python 3 wrapper for Windows Debugging Tools debugger cdb.exe. Cdb allows for advanced debugger scripting and flexability. many methods implemented within Cdb could be manually implemented if the need arises.

Heavily based on the PyCDB code from fishstiqz.

Happy debugging!
    """,
    version='0.1',
    author='@debugregister',
    maintainer='@debugregister',
    author_email='',
    url='https://github.com/debugregister/pycdb',
    platforms='Microsoft Windows',
    install_requires = open(os.path.join(os.path.dirname(__file__), "requirements.txt")).read().split("\n"),
    classifiers = ['Programming Language :: Python :: 3'],
    scripts = [],

    package_data = {
        "cdb": [],
    },
    include_package_data=False,

    # include all modules/submodules here
    packages=['pycdb']
)