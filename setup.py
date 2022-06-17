import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ts1-signatures",
    version="0.1.4",
    author="lwthiker",
    author_email="lwt@lwthiker.com",
    description="TLS and HTTP signature and fingerprint library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lwthiker/ts1",
    project_urls={
        "Bug Tracker": "https://github.com/lwthiker/ts1/issues"
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"
    ],
    install_requires=["dpkt"],
    packages=["ts1"],
    python_requires=">=3.2"
)
