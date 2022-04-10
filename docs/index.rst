Mistyfy
=================
A package that helps encrypts strings and returns an encrypted version of it.


Install
-----------------
Install using `pip`. You have to be on python >= 3.6.x in order to utilize this script.

* Download python and install on your device by visiting `python.org <https://python.org/download>`_
* Run the below command either using a virtual environment or from your python alias

.. code-block:: bash

    pip install mistyfy
    
OR

.. code-block:: bash

    python3 - m pip install mistyfy
    

How to use it
-----------------

.. code-block:: python

 from mistyfy import encode, decode, ciphers, generator
 import os
 # ciphers is a dictionary containing ascii characters, you can change this at will
 # use the generator function to create your own unique cipher
 gn = generator(ciphers, -400, 138192812) # first arg is the cipher block, 
 # second & third arg is the start and stop counter
 secret = b'somesecretkey' # create any secret key, easier if you use os.urandom(n)
 # secret = os.urandom(16)
 a = "This is a secret message or password"
 b = encode(a, secret, gn) 
 # output is a dictionary which contains a signed value when decrypting:
 # eyJtaXN0eWZ5IjogWzQ5Nxxxxxx...
 c = decode(b, secret, gn)
 # Output:
 # This is a secret message or password
 # Output: if the secret is wrong
 # Failure decrypting data
 
 
Use cases
-----------------

* Safely store a password or token, validate that it is signed before it can be decoded.
* Transmit a large set of encrypted strings.
* Create your own cipher block and be the only one who can decrypt it.

There are other part of the script you can use. To easily create a password checking system use signs and `verify_signs` function, this takes a similar example given by python doc for hashlib but with the ability to add a secret.


.. code-block:: python

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
 
 

API Reference
---------------
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
