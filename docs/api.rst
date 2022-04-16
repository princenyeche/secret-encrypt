API
=====================

.. module:: mistyfy

The below shows all the available functions and variables within this module.

Ciphers
-----------

A dictionary object variable which contains a curated list of ascii or utf-8 characters. This object can be mutated into whatever character
structure you want by importing it and change every character.

By default it comes with `225` characters. Which includes alphanumeric and special characters

.. code-block:: python

 import mistyfy as ms
 
 ms.ciphers = {} # denoting new characters which can be mutated.
 
 
.. autofunction:: generator

.. autofunction:: encode

.. autofunction:: decode

.. autofunction:: signs

.. autofunction:: verify_signs
