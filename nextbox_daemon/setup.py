import os
from setuptools import setup

setup(
    name = "NextBox Daemon",
    version = "0.0.1",
    author = "Markus Meissner - Nitrokey",
    author_email = "meissner@nitrokey.com",
    description = "The Nitrokey - NextBox System Control Daemon",
    license = "GPL",
    packages = ["nextbox_daemon"],
    classifiers=[
        "Development Status :: 3 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: GPL License",
    ],
)
