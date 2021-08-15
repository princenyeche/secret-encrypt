#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a simple algorithm that provides you the option
to encrypt a series of strings in your own way, pass that string encoded up to 3 layers,
send the data over the internet and decrypt the original data.
The wonderful part of this module is that you can have a vast amount of
text which little object size.
"""
import base64 as b
import hashlib
import hmac
import json as jo
import typing as t
import random as rt

# static created ciphers to use
ciphers = {
    'a': chr(15), 'b': 2, 'c': chr(3), 'd': 4,

    'e': 5, 'f': 6, 'g': 7, 'h': 8,

    'i': 9, 'j': 10, 'k': 11, 'l': chr(12),

    'm': chr(13), 'n': chr(14), 'o': 15, 'p': 16,

    'q': 17, 'r': 18, 's': chr(19), 't': 20,

    'u': 21, 'v': 22, 'w': 23, 'x': 24,

    'y': 25, 'z': 26, ' ': 100, 'A': 101,

    'B': 102, 'C': 103, 'D': 30, 'E': 104,

    'F': 105, 'G': 106, 'H': 107, 'I': 108,

    'J': 109, 'K': hex(110), 'L': 111, 'M': 112,

    'N': 113, 'O': 114, 'P': 115, 'Q': 116,

    'R': 117, 'S': 118, 'T': 119, 'U': 120,

    'V': 121, 'W': 122, 'X': 123, 'Y': 124,

    'Z': 125, '.': 200, '/': 201, '\\': 202,

    '$': 203, '#': 204, '@': 205, '%': 206,

    '^': 207, '*': 208, '(': 209, ')': 210,

    '_': 211, '-': 212, '=': 213, '+': 214,

    '>': 215, '<': 216, '?': 217, ';': 218,

    ':': 219, '\'': 220, '\"': 221, '{': 222,

    '}': 223, '[': 224, ']': 225, '|': 226,

    '`': 227, '~': 228, '!': 229, '0': 300,

    '1': 301, '2': 302, '3': 303, '4': 304,

    '5': 306, '6': 307, '7': 308, '8': 309,

    '9': 310, '\n': 311, '\r': 312, '\t': 313
}


def generator(cipher: dict, start: int = 70, stop: int = 1000) -> dict:
    """Generates a random unique number for each characters.
    :param cipher: A pseudo series of text

    :param start: An integer to begin from

    :param stop: An integer to stop

    :return: A dictionary having unique numbers for your cipher
    """
    data_set = set()
    length = len(cipher)
    for x in cipher:
        stage = rt.randint(start, stop)
        cipher[x] = stage
        data_set.add(cipher[x])
    if length > len(data_set):
        generator(cipher, start, stop + 7)
    if length <= len(data_set):
        for j, s in zip(cipher, data_set):
            cipher[j] = s
    return cipher


def encode(data: str, secret: bytes, cipher: t.Optional[dict] = None) -> t.Union[t.Dict[str, bytes], str]:
    """
     Encrypts a given string and send an output
    :param data: a string value

    :param secret: A secret key in bytes.

    :param cipher: a pseudo randomizer

    :return: dictionary with signature and the data in bs64(when decrypted returns list of numbers)
    """
    try:
        if not isinstance(data, str):
            raise
        else:
            gain = []
            if cipher is None:
                raise TypeError('Expecting a series of cipher for each character.')
            # do a loop through the strings and interchange it with numbers
            for i in data:
                # get the value from the dictionary
                k = cipher[i]
                if i in cipher:
                    # append the value in a list
                    gain.append(k)
            transform = {"mistyfy": gain}
            f = jo.dumps(transform)  # change the list into a string
            s = bytes(f, 'utf-8')  # encode the string into bytes
            export = b.b64encode(s)  # bs64 encode the bytes
            # return a hash with a secret key
            return {"signature": signs(export, secret=secret), "data": export}
    except ValueError as e:
        if e:
            return "You are using the wrong data type, expecting a string as data."
        return "Failure encrypting data"


def decode(data: dict, secret: bytes, cipher: t.Optional[dict] = None) -> str:
    """
     Decrypts a dictionary and sends output as string
    :param data: A byte of data from dictionary

    :param secret: A super secret key in bytes

    :param cipher: a pseudo randomizer

    :return: String of the decrypted data.
    """
    try:
        if not isinstance(data, dict):
            raise
        else:
            if cipher is None:
                raise TypeError('Expecting a series of cipher for each character.')
            # get the signature of the signed data
            decrypt = signs(data['data'], secret=secret)
            # validate that the signature is indeed correct with the data that was received.
            validate_signature = verify_signs(decrypt, data['signature'])
            if validate_signature is True:
                port = b.b64decode(data['data'])  # decode bs64 encrypted data
                key = bytes.decode(port, encoding='utf-8')  # decode from bytes
                parse = []
                j = jo.loads(key).get('mistyfy')
                # find the key value of the encoded numbers
                for x in j:
                    for k, v in cipher.items():
                        if x == v:
                            parse.append(k)
                # return a string output
                return "".join(parse)
            else:
                return "Unable to decrypt data, incorrect value."
    except ValueError as e:
        if e:
            return "You are using the wrong data type, expecting data to be a characters in bytes."
        return "Failure decrypting data"


def signs(data, secret, auth_size=16) -> bytes:
    """Using blake2b, a set of encryption algorithms to sign our data.
    :param data: The byte of data,

    :param secret: A secret key

    :param auth_size: digest size key

    :return: Bytes of encrypted hash.
    """
    h = hashlib.blake2b(digest_size=auth_size, key=secret)
    h.update(data)
    return h.hexdigest().encode('utf-8')


def verify_signs(data: bytes, signature: bytes) -> bool:
    """Verify that a signed byte is indeed the right hash.
    :param data: A byte of encrypted data

    :param signature: A signed hash

    :return: A boolean value to confirm True of False of signed hash.
    """
    return hmac.compare_digest(data, signature)
