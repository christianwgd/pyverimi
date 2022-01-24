import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyyes",
    version="0.0.1",
    author="Daniel Fett",
    author_email="danielf@yes.com",
    description="A python implementation of the yes® identity and signing flows",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yescom/pyyes",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=["furl", "PyJWT", "pyHanko[pkcs11]==0.8.0"],
)
