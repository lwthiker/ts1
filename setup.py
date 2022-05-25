import setuptools

setuptools.setup(
    name="ts1",
    version="0.1.0",
    author="lwthiker",
    author_email="lwt@lwthiker.com",
    description="Process and compare browser TLS & HTTP fingerprints",
    long_description="file: README.md",
    long_description_content_type="text/markdown",
    url="https://github.com/lwthiker/websig",
    project_urls={
        "Bug Tracker": "https://github.com/lwthiker/websig/issues"
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"
    ],
    install_requires=["dpkt"],
    package_dir={"": "ts1"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.2"
)
