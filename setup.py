from setuptools import setup, find_packages

setup(
    name="cloudguard",
    version="0.1.0",
    description="IaC and live AWS cloud misconfiguration scanner",
    author="Yash Chavan",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "python-hcl2>=8.0.0",
        "boto3>=1.34.0",
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": ["pytest>=8.0.0"],
    },
    entry_points={
        "console_scripts": [
            "cloudguard=cloudguard.cli:cli",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
