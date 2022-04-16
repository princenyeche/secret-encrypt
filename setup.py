import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mistyfy",
    version="2.0.3",
    author="Prince Nyeche",
    author_email="support@elfapp.website",
    description="A package that helps encrypt any given string and returns an encrypted string with a signed hash."
                "This data can be sent over the internet and only you will know "
                "how to decrypt it because you control the cipher.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/princenyeche/mistyfy",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
