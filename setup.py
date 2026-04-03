from setuptools import setup, find_packages

setup(
    name="netser-signatures",
    version="0.1.0",
    description="Network service signature detection library",
    author="netser-signatures",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.7",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "netser-detect=netser_signatures.cli:main",
        ],
    },
)
