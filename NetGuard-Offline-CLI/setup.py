from setuptools import setup, find_packages

setup(
    name="netguard-cli",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "numpy",
        "pandas",
        "torch",
        "scikit-learn",
        "joblib",
        "scapy",
        "pyarrow",
    ],
    entry_points={
        "console_scripts": [
            "netguard=main:main",
        ],
    },
)
