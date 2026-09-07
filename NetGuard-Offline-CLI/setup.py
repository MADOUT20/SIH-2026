from setuptools import setup, find_packages

setup(
    name="netguard-cli",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "numpy==1.26.4",
        "pandas==2.2.2",
        "torch",
        "scikit-learn==1.5.1",
        "joblib==1.3.2",
    ],
    entry_points={
        "console_scripts": [
            "netguard=main:main",
        ],
    },
)
