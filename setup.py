from setuptools import setup
from setuptools import find_packages


def readme():
    with open('README.md', 'r') as f:
        return f.read()

setup(
    name = 'accutil',
    description = "A tool for automating interaction with the LDR ingress " +
    "microservice",
    long_description = readme(),
    version = '0.0.1dev',
    author = "Brian Balsamo",
    author_email = "balsamo@uchicago.edu",
    keywords = [
        "uchicago",
        "repository",
        "file-level",
        "processing"
    ],
    packages = find_packages(
        exclude = [
            "build",
            "bin",
            "dist",
        ]
    ),
    entry_points = {
        'console_scripts':[
            'accession = accutil:launch',
        ]
    },
    classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Operating System :: Unix",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires = [
        'requests>0',
        'requests-toolbelt'
    ]
)
