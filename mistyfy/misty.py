#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a simple algorithm that provides you the option
to encrypt a series of strings in your own way, pass that string encoded
up to 2 layers, send the data over the internet and decrypt the original data.
The wonderful part of this module is that you can have a vast amount of
text which is of little object size.
"""
import base64 as b
import hashlib
import hmac
import json as jo
import typing as t
import random as rt
import datetime

# A static created ciphers to use - possible ascii or utf-8 characters
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


def generator(
        cipher: dict,
        start: int = 70,
        stop: int = 1000,
        fmt: bool = True) -> t.Union[str, dict]:
    """Generates a random unique number for each characters.

    .. code-block:: python

      from mistyfy import ciphers, generator
      import json
      import os

      if not os.path.exists('../data/config.json'):
          gen = generator(ciphers, -400, 13931283)
          json.dump(gen, open('../data/config.json', mode='w+',
                   encoding='utf-8'), indent=4, sort=True)


      if __name__ == "__main__":
           if os.path.isfile('../data/config.json'):
              data = json.dumps(json.load(open('../data/config.json')))
              print(data)


    .. versionadded:: 2.0.0
    fmt argument - Exports the cipher format in string if true,
                   dictionary if false.

    :param cipher: A pseudo series of text

    :param start: An integer to begin our randomization from

    :param stop: An integer to our stop randomization

    :param fmt: Exports the cipher format in string if true,
                dictionary if false.

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
    return jo.dumps(cipher) if fmt is True else cipher


def encode(
        data: str,
        secret: str,
        cipher: t.Union[str, dict] = None,
        expire: int = 3600,
        **kwargs: t.Any) -> str:
    """
     Encrypts a given string and send an output.

     .. code-block:: python

      from mistyfy import encode, ciphers, generator
      import os

      gn = generator(ciphers, -400, 138192812)

      # create any secret key, easier if you use os.urandom(n)
      secret = b'somesecretkey'
      # secret = os.urandom(16)
      a = "This is a secret message or password"
      b = encode(a, secret, gn)
      # output is a string base64, encoded with a signature,
      # and mistyfied with the cipher.
      # eyJtaXN0eWZ5IjogWzQ5Nxxxxxx...


     The generator function helps to create a cipher. Ciphers is a dictionary
     containing ascii or utf-8 characters, you can change this at will using
     the generator function to create your own unique cipher.
     The first argument is the cipher block, second & third argument is the
     start and stop counter.

     .. versionadded:: 2.0.0
    expire argument - The number of seconds an encoded data can last for.
    This timestamp is in UTC. By default it is set to 1 hour from the
    initial encoded time.

    :param data: a string value

    :param secret: A secret key.

    :param cipher: a pseudo randomizer

    :param expire: The number of seconds an encoded data can last for.

    :param kwargs: Additional parameters you can add to hashlib

               *options*

               auth_size: integer - If used in encode, the same size must be
               used for decode, taken from arguments from blake2b

               key: Union[bytes, bytearray, memoryview,
                                 array, mmap, mmap] = ...,

               salt: Union[bytes, bytearray, memoryview,
                                  array, mmap, mmap] = ...,

               person: Union[bytes, bytearray, memoryview,
                                  array, mmap, mmap] = ...,

               fanout: int = ...,

               depth: int = ...,

               leaf_size: int = ...,

               node_offset: int = ...,

               node_depth: int = ...,

               inner_size: int = ...,

               last_node: bool = ...,

               usedforsecurity: bool = ...


    :return: string with signature and the data in
                                 bs64(when decrypted returns list of numbers)
    """
    _secret = str(secret)
    secret = _secret
    try:
        if not isinstance(data, str):
            raise TypeError("Expected `data` argument to strings "
                            "got {} instead".format(type(data)))
        else:
            gain = []
            if cipher is None:
                raise TypeError("Expecting a series of cipher for "
                                "each character.")
            # do a loop through the strings and interchange it with numbers
            if isinstance(cipher, str):
                _cipher = jo.loads(cipher)
                cipher = _cipher
            for i in data:
                # get the value from the dictionary
                k = cipher[i]
                if i in cipher:
                    # append the value in a list
                    gain.append(k)
            transform = {"mistyfy": gain}
            f = jo.dumps(transform)  # change the list into a string
            s = f.encode("utf-8")  # encode the string into bytes
            _encode = b.b64encode(s)  # bs64 encode the bytes
            # make the bytes a string instead
            decode_ = _encode.decode("utf-8")
            # put a timestamp to the request, default is 3600 seconds
            make_time = datetime.datetime.utcnow()
            future = make_time + datetime.timedelta(seconds=expire)
            # format the time into strings
            str_fmt = future.strftime("%Y-%m-%d %H:%M:%S.%f")
            # this will contain a signed signature of the data
            sig = signs(decode_, secret, **kwargs)
            # return a string of the encoded data
            encode_export = jo.dumps({"data": decode_, "expire": str_fmt,
                                      "signature": sig})
            # bs64 the data again
            results = b.b64encode(encode_export.encode("utf-8"))
            _do_results = results.decode("utf-8")  # ensure its in strings
            return _do_results
    except Exception as error:
        if isinstance(error, ValueError):
            return "You seem to be using some wrong data format. " \
                   "Check your entered data."
        return "Failure encrypting data."


def decode(
        data: str,
        secret: str,
        cipher: t.Optional[str] = None,
        **kwargs: t.Any) -> str:
    """
     Decrypts a data and sends output as string. Usually the original form of
     an encoded data.

     .. code-block:: python

      from mistyfy import encode, decode, ciphers, generator
      import os

      gn = generator(ciphers, -400, 138192812)
      secret = os.urandom(16)
      a = "This is a secret message or password"
      b = encode(a, secret, gn)
      # output is a string
      # eyJtaXN0eWZ5IjogWzQ5Nxxxxxx...
      # decode the data with the below
      c = decode(b, secret, gn)
      # Output:
      # This is a secret message or password

    :param data: A strings of encoded data

    :param secret: A super secret key

    :param cipher: a pseudo randomizer

    :param kwargs: Additional parameters you can add to hashlib

               *options*

               auth_size: integer - If used in encode, the same
               size must be used for decode taken from arguments from blake2b

               key: Union[bytes, bytearray, memoryview,
                             array, mmap, mmap] = ...,

               salt: Union[bytes, bytearray, memoryview,
                            array, mmap, mmap] = ...,

               person: Union[bytes, bytearray, memoryview,
                            array, mmap, mmap] = ...,

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
    _secret = str(secret)
    secret = _secret
    try:
        if not isinstance(data, str):
            raise TypeError("Expected your `data` argument to be "
                            "strings got {} instead".format(type(data)))
        else:
            if cipher is None:
                raise TypeError('Expecting a series of cipher for '
                                'each character.')
            # validate that the signature is indeed correct with
            # the data that was received.
            if isinstance(cipher, str):
                _cipher = jo.loads(cipher)
                cipher = _cipher
            _decode_result = data.encode("utf-8")  # encode into bytes
            # decode into strings
            results = b.b64decode(_decode_result).decode("utf-8")
            get_dict = jo.loads(results)
            validate_signature = verify_signs(get_dict['data'],
                                              get_dict['signature'],
                                              secret=secret, **kwargs)
            if validate_signature is True:
                # check if the time has expired
                if get_dict["expire"]:
                    current_time = datetime.datetime.utcnow()
                    if datetime.datetime. \
                            strptime(get_dict["expire"],
                                     "%Y-%m-%d %H:%M:%S.%f") > current_time:
                        pass
                    else:
                        return "Unable to validate data as token has expired."

                # decode bs64 encrypted data
                port = b.b64decode(get_dict['data'])
                key = port.decode("utf-8")  # decode from bytes
                parse = []
                j = jo.loads(key).get('mistyfy')
                # find the key value of the encoded numbers
                for x in j:
                    for k, v in cipher.items():
                        if x == v:
                            parse.append(k)
                # return a string output
                return "".join(parse) \
                    if len(parse) != 0 else "Empty value " \
                                            "detected. Decryption failed."
            else:
                return "Unable to decrypt data, incorrect value detected."
    except Exception as error:
        if isinstance(error, ValueError):
            return "You seem to be using the wrong data value or maybe the data " \
                   "used as value in the data argument is incorrect."
        return "Failure decrypting data."


def signs(
        data: t.Any,
        secret: str,
        auth_size=16,
        **kwargs) -> str:
    """Using blake2b, a set of encryption algorithms to sign our data.

    .. code-block:: python

     from mistyfy import signs

     secret = "somesecretstuff"
     password = "mypasswordstuff"

     code = signs(password, secret)
     # result
     # c2342328dhsjxxxxxx

    :param data: Any data value,

    :param secret: A secret key

    :param auth_size: digest size key

    :return: strings of encrypted hash.
    """
    _data, _secret = str(data), secret.encode("utf-8")
    data, secret = _data, _secret
    h = hashlib.blake2b(digest_size=auth_size, key=secret, **kwargs)
    h.update(data.encode("utf-8"))
    _encode = h.hexdigest().encode('utf-8')
    return _encode.decode("utf-8")


def verify_signs(
        data: t.Any,
        signature: str,
        **kwargs) -> bool:
    """Verify that a signed byte is indeed the right hash.

    .. code-block:: python

     from mistyfy import verify_signs, signs

     secret = "somesecretstuff"
     password = "mypasswordstuff"
     code = signs(password, secret)

     reveal = verify_signs(password, code, secret=secret)
     # result
     # mypasswordstuff

    :param data: Any encrypted data

    :param signature: A signed hash

    :param kwargs: Additional arguments to use

            auth_size: Authenticate key passed to signs function.

            secret: A secret key passed to signs function
            You can also use the same arguments applicable to blake2b
            and they are passed to the signs function.

    :return: A boolean value to confirm True of False of signed hash.
    """
    _data = str(data)
    data = _data
    if "secret" not in kwargs:
        raise NameError("You're missing the `secret` keyword argument. "
                        "E.g secret='somesecrete'")
    confirm = signs(data, **kwargs)
    return hmac.compare_digest(confirm, signature)
