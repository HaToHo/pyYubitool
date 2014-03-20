# -*- coding: utf-8 -*-
from distutils.core import setup

setup(
    name="pyYubitool",
    version="0.1",
    description='Python yubikey tool. Contains client and server code.',
    author = "Hans, Hoerberg",
    author_email = "hans.horberg@umu.se",
    license="Apache 2.0",
    package_dir = {"": "src"},
    classifiers = ["Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires = [],
    scripts=[],
    zip_safe=False,
    packages=['pyYubitool'],
    data_files=[]

)