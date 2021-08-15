#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A package that helps encrypts any given string and returns
an encrypted string with a signed hash.
This data can be sent over the internet and only you will know
how to decrypt it because you control the cipher.
"""
from mistyfy.algo import encode, decode, ciphers, signs, verify_signs, generator

__all__ = ["encode", "decode", "ciphers", "signs", "verify_signs", "generator"]
__version__ = "v1.0.0"
__author__ = "Prince Nyeche"
