[![Codacy Badge](https://app.codacy.com/project/badge/Grade/b00ef172196949319f43b12e6bc3f4ae)](https://www.codacy.com/gh/princenyeche/mistyfy/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=princenyeche/mistyfy&amp;utm_campaign=Badge_Grade)
[![Downloads](https://pepy.tech/badge/mistyfy)](https://pepy.tech/project/mistyfy)
[![PyPI version](https://badge.fury.io/py/mistyfy.svg)](https://badge.fury.io/py/mistyfy)
![GitHub](https://img.shields.io/github/license/princenyeche/mistyfy)
[![Documentation Status](https://readthedocs.org/projects/mistyfy/badge/?version=latest)](https://mistyfy.readthedocs.io/en/latest/?badge=latest)
[![Build Status](https://app.travis-ci.com/princenyeche/mistyfy.svg?branch=main)](https://app.travis-ci.com/princenyeche/mistyfy)

# Mistyfy
A package that helps encrypt any given string and returns an encrypted version of it. This package is very pythonic and has no dependencies. You can expand on it but it gives you the ability to encrypt data in a way only you can understand.

# Install
You should download python, any version from 3.6.x will do. This should come with pip and you can
 use `pip install mistyfy` to complete the installation.

# How to use it
```python
from mistyfy import encode, decode, ciphers, generator
import os
# ciphers is a dictionary containing ascii characters, you can change this at will
# use the generator function to create your own unique cipher
gn = generator(ciphers, -400, 138192812) # first arg is the cipher block, second & third arg is the start and stop counter
secret = b'somesecretkey' # create any secret key, easier if you use os.urandom(n)
# secret = os.urandom(16)
a = "This is a secret message or password"
b = encode(a, secret, gn) 
# output is a dictionary which contains a signed value when decrypting:
# 'eyJtaXN0eWZ5IjogWzQ5Nxxxxxx...
c = decode(b, secret, gn)
# Output:
# This is a secret message or password
# Output: if the secret is wrong
# Failure decrypting data
```
# Use cases
* Safely store a password or token, validate that it is signed before it can be decoded.
* Transmit a large set of encrypted strings.
* Create your own `cipher block` and be the only one who can decrypt it.

There are other part of the script you can use. To easily create a password checking system use `signs` and `verify_signs` function, this takes a similar example given by python doc for hashlib but with the ability to add a secret.
```python
from mistyfy import signs, verify_signs

secrets = 'someimportstuff'
password = 'myverypassword'

encrypt_decrypt = signs(password, secret=secrets)
print(encrypt_decrypt)
# cfe13a4eef4e9c9ccbedf4ec05873ed0
# verify takes into two arguments and 1 required keyword arg to compare if their hashes are the same
# in this situation, the signed data and the actual outcome.                                                                                                                                                                                                  
verify = verify_signs(password, encrypt_decrypt, secret=secrets)
if verify is True:
    print('User is valid')
else:
    print('User is not valid')

# Output
# User is valid
```

