#!/usr/bin/env python3
"""Setup script for shallot-cli (fallback for editable install issues)."""

from setuptools import setup, find_packages
import os

# Ensure we pick up shallot_cli in the repo root
here = os.path.dirname(os.path.abspath(__file__))

setup(
    name="shallot-cli",
    version="0.1.0",
    description="CLI tool for syncing and flashing SHALLOT firmware",
    packages=find_packages(where=here, include=["shallot_cli", "shallot_cli.*"]),
    package_dir={"": here},
    install_requires=[],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "shallot=shallot_cli.cli:main",
        ],
    },
)
