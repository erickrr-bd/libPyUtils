from setuptools import setup, find_packages

setup(
    name = "libPyUtils",
    version = "2.2",
    author = "Erick Rodriguez",
    description = "Modular collection of features and tools designed to make Python application development easier.",
    long_description = open("README.md", encoding = "utf-8").read(),
    long_description_content_type = "text/markdown",
    packages = find_packages(),
    install_requires = ["pycryptodomex", "PyYAML", "psutil"],
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL-3.0",
        "Operating System :: OS Independent",
    ],
    python_requires = ">=3.12",
)