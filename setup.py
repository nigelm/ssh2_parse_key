#!/usr/bin/env python
"""The setup script."""
from setuptools import find_packages
from setuptools import setup

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()

requirements = ["classforge"]

setup_requirements = [
    "pytest-runner",
    "wheel",
]

test_requirements = [
    "pytest>=3",
]

setup(
    author="Nigel Metheringham",
    author_email="nigelm@cpan.org",
    python_requires=">=3.5",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    description="Parses ssh2 keys and converts to multiple formats.",
    install_requires=requirements,
    license="MIT license",
    long_description=readme + "\n\n" + history,
    include_package_data=True,
    keywords="ssh2_parse_key",
    name="ssh2_parse_key",
    packages=find_packages(include=["ssh2_parse_key", "ssh2_parse_key.*"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/nigelm/ssh2_parse_key",
    version="0.1.0",
    zip_safe=False,
)
