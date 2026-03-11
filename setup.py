"""Setup script for ai-waf package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip() for line in fh if line.strip() and not line.startswith("#")
    ]

setup(
    name="ai-waf",
    version="0.1.0",
    author="AI-WAF Contributors",
    description="AI-Powered Web Application Firewall",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ai-waf/ai-waf",
    packages=find_packages(exclude=["tests*", "training*", "docker*", "docs*"]),
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ai-waf=waf.app:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    include_package_data=True,
    package_data={
        "waf": ["config/*.yaml", "rules/*.yaml"],
    },
)
