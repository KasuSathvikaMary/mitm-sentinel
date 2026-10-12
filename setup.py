from setuptools import setup, find_packages

setup(
    name="mitm-sentinel",
    version="1.0.0",
    author="Kasu Sathvika Mary",
    author_email="kasusathvika@gmail.com",
    description="Man-in-the-Middle (MITM) Attack Prevention & Detection System with Autonomous Defense",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "pydantic>=2.0.0",
        "requests>=2.28.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "websockets>=11.0",
        "cryptography>=41.0.0",
        "pytest>=7.4.0"
    ],
    entry_points={
        "console_scripts": [
            "mitm-sentinel=src.main:main",
        ],
    },
)
