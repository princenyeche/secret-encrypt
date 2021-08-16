#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a simple algorithm that provides you the option
to encrypt a series of strings in your own way, pass that string encoded up to 2 layers,
send the data over the internet and decrypt the original data.
The wonderful part of this module is that you can have a vast amount of
text which is of little object size.
"""
import base64 as b
import hashlib
import hmac
import json as jo
import typing as t
import random as rt

# A static created ciphers to use - possible ascii characters
# you can mutate this into more ascii characters known to you.
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
    '9': 310, '\n': 311, '\r': 312, '\t': 313,
    ',': 315, '—': 316, 'è': 317, 'ü': 318, 'â': 319,
    'ä': 401, 'à': 501, 'å': 601, 'ç': 701, 'ê': 801,
    'ë': 402, 'é': 502, 'ï': 602, 'î': 702, 'ì': 802,
    'Ä': 403, 'Å': 503, 'É': 603, 'æ': 703, 'Æ': 803,
    'ô': 404, 'ö': 504, 'ò': 604, 'û': 704, 'ù': 804,
    'ÿ': 405, 'Ö': 505, 'Ü': 605, 'ø': 705, '£': 805,
    'Ø': 406, '×': 506, 'ƒ': 606, 'á': 706, 'í': 806,
    'ó': 407, 'ú': 507, 'ñ': 607, 'Ñ': 707, 'ª': 807,
    'º': 408, '¿': 508, '®': 608, '¬': 708, '½': 808,
    '¼': 409, '¡': 509, '«': 609, '»': 709, '░': 809,
    '▒': 410, '▓': 510, '│': 610, '┤': 710, 'Á': 810,
    'Â': 411, 'À': 511, '©': 611, '╣': 711, '║': 811,
    '╗': 412, '╝': 512, '¢': 612, '¥': 712, '┐': 812,
    '└': 413, '┴': 513, '┬': 613, '├': 713, '─': 813,
    '┼': 414, 'ã': 514, 'Ã': 614, '╚': 714, '╔': 814,
    '╩': 415, '╦': 515, '╠': 615, '═': 715, '╬': 815,
    '¤': 416, 'ð': 516, 'Ð': 616, 'Ê': 716, 'Ë': 816,
    'È': 417, 'ı': 517, 'Í': 617, 'Î': 717, 'Ï': 817,
    '┘': 418, '┌': 518, '█': 618, '▄': 718, '¦': 818,
    'Ì': 419, '▀': 519, 'Ó': 619, 'ß': 719, 'Ô': 819,
    'Ò': 420, 'õ': 520, 'Õ': 620, 'µ': 720, 'þ': 820,
    'Þ': 421, 'Ú': 521, 'Û': 621, 'Ù': 721, 'ý': 821,
    'Ý': 422, '¯': 522, '´': 622, '≡': 722, '±': 822,
    '‗': 423, '¾': 523, '¶': 623, '§': 723, '÷': 823,
    '¸': 424, '°': 524, '¨': 624, '·': 724, '¹': 824,
    '³': 425, '²': 525, '■': 625, '&': 725
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


def encode(data: str,
           secret: bytes,
           cipher: t.Optional[dict] = None,
           **kwargs: t.Any) -> t.Union[t.Dict[str, bytes], str]:
    """
     Encrypts a given string and send an output
    :param data: a string value

    :param secret: A secret key in bytes.

    :param cipher: a pseudo randomizer

    :param kwargs: Additional parameters you can add to hashlib
               options
               *auth_size: integer - If used in encode, the same size must be used for decode
               *Taken from arguments from blake2b
               key: Union[bytes, bytearray, memoryview, array, mmap, mmap] = ...,
               salt: Union[bytes, bytearray, memoryview, array, mmap, mmap] = ...,
               person: Union[bytes, bytearray, memoryview, array, mmap, mmap] = ...,
               fanout: int = ...,
               depth: int = ...,
               leaf_size: int = ...,
               node_offset: int = ...,
               node_depth: int = ...,
               inner_size: int = ...,
               last_node: bool = ...,
               usedforsecurity: bool = ...

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
            return {"signature": signs(export, secret=secret, **kwargs), "data": export}
    except ValueError as e:
        if e:
            return "You are using the wrong data type, expecting a string as data."
        return "Failure encrypting data"


def decode(data: dict,
           secret: bytes,
           cipher: t.Optional[dict] = None,
           **kwargs: t.Any) -> str:
    """
     Decrypts a dictionary and sends output as string
    :param data: A byte of data from dictionary

    :param secret: A super secret key in bytes

    :param cipher: a pseudo randomizer

    :param kwargs: Additional parameters you can add to hashlib
               options
               *auth_size: integer - If used in encode, the same size must be used for decode
               *Taken from arguments from blake2b
               key: Union[bytes, bytearray, memoryview, array, mmap, mmap] = ...,
               salt: Union[bytes, bytearray, memoryview, array, mmap, mmap] = ...,
               person: Union[bytes, bytearray, memoryview, array, mmap, mmap] = ...,
               fanout: int = ...,
               depth: int = ...,
               leaf_size: int = ...,
               node_offset: int = ...,
               node_depth: int = ...,
               inner_size: int = ...,
               last_node: bool = ...,
               usedforsecurity: bool = ...

    :return: String of the decrypted data.
    """
    try:
        if not isinstance(data, dict):
            raise
        else:
            if cipher is None:
                raise TypeError('Expecting a series of cipher for each character.')
            # validate that the signature is indeed correct with the data that was received.
            validate_signature = verify_signs(data['data'], data['signature'], secret=secret, **kwargs)
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
            return "You are using the wrong data type, expecting data to be characters in bytes."
        return "Failure decrypting data"


def signs(data: bytes, secret: bytes, auth_size=16, **kwargs) -> bytes:
    """Using blake2b, a set of encryption algorithms to sign our data.
    :param data: The byte of data,

    :param secret: A secret key

    :param auth_size: digest size key

    :return: Bytes of encrypted hash.
    """
    h = hashlib.blake2b(digest_size=auth_size, key=secret, **kwargs)
    h.update(data)
    return h.hexdigest().encode('utf-8')


def verify_signs(data: bytes, signature: bytes, **kwargs) -> bool:
    """Verify that a signed byte is indeed the right hash.
    :param data: A byte of encrypted data

    :param signature: A signed hash

    :param kwargs: Additional arguments to use
             auth_key: Authenticate key passed to signs function
             secret: A secret key passed to signs function
             You can also use the same arguments applicable to blake2b
            and they are passed to the signs function.

    :return: A boolean value to confirm True of False of signed hash.
    """
    confirm = signs(data, **kwargs)
    return hmac.compare_digest(confirm, signature)
