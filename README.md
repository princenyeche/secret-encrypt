# Mistyfy
A package that helps encrypts any given string and returns an encrypted version of it.

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
# {'signature': b'02865b8419c0f4f541e2d31615d4f7c1', 'data': b'eyJtaXN0eWZ5IjogWzQ5Nxxxxxx...'}
c = decode(b, secret, gn)
# Output:
# This is a secret message or password
# Output: if the secret is wrong
# Failure decrypting data
```
# Use cases
* Safely store a password or token validate that it is signed before it can be decoded.
* Transmit a large set of strings encrypted with the smallest size possible .
* Create your own `cipher block` and be the only one who can decrypt it.
