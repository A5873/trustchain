from setuptools import setup, find_packages

setup(
    name="trustchain",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=39.0.0",
        "requests>=2.28.0",
        "pydantic>=2.0.0",
        "typer>=0.9.0",
        "rich>=13.3.0",
        "aiohttp>=3.8.0",
        "PyYAML>=6.0",
        "toml>=0.10.2",
        "msgpack>=1.0.5",
        "fastapi>=0.95.0",
        "cffi>=1.15.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.3.1",
            "black>=23.3.0",
            "isort>=5.12.0",
            "mypy>=1.2.0",
            "pylint>=2.17.0",
            "pytest-cov>=4.1.0",
        ],
        "ui": [
            "plotly>=5.14.0",
            "dash>=2.9.0",
            "streamlit>=1.22.0",
        ],
        "integrations": [
            "docker>=6.1.0",
            "kubernetes>=26.1.0",
            "GitPython>=3.1.31",
        ],
    },
    entry_points={
        "console_scripts": [
            "trustchain-py=trustchain.cli:main",
        ],
    },
    python_requires=">=3.10",
    author="TrustChain Team",
    author_email="info@trustchain.com",
    description="Secure Open Source Supply Chain Infrastructure",
    long_description=open("../../README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/trustchain/trustchain",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development",
    ],
)

