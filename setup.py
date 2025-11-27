"""Setup configuration for RDIGuard"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="rdiguard",
    version="5.0.0",
    author="Joe R. Miller",
    author_email="joemiller137@gmail.com",
    description="Non-Markovian SSH attack detection using entropy-based regularity analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SeeingIn5D/rdiguard",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.19.0",
        "pyyaml>=5.3.0",
    ],
    extras_require={
        "alerts": ["requests>=2.25.0"],
        "dev": ["pytest>=7.0.0"],
    },
)
