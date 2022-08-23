#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
A package that helps encrypt any given string and returns
an encrypted string with a signed hash.
This data can be sent over the internet and only you will know
how to decrypt it because you control the cipher.
"""
from mistyfy.misty import encode, decode, ciphers, signs, verify_signs, generator

__all__ = ["encode", "decode", "ciphers", "signs", "verify_signs", "generator"]
__version__ = "v2.0.6"
__author__ = "Prince Nyeche"
__copyright__ = "MIT License"
