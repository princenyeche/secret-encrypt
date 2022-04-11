from mistyfy import encode, decode, ciphers, generator, signs, verify_signs
import unittest
import os

SECRET = os.environ.get("SECRET_MISTYFY") or ""
STRING_BLOCK = """
Latin script
Main article: Latin script in Unicode
The Unicode Standard (version 13.0) classifies 1,374 characters as belonging to the Latin script.

Basic Latin
Main article: Basic Latin (Unicode block)
"Special characters" redirects here. For the Wikipedia editor's handbook page, see Help:Special characters.
See also: ASCII § ASCII printable characters

95 characters; the 52 alphabet characters belong to the Latin script. The remaining 43 belong to the common script.
The 33 characters classified as ASCII Punctuation & Symbols are also sometimes referred to as ASCII special characters.
See § Latin-1 Supplement and § Unicode symbols for additional "special characters". Certain special characters can be
used in passwords; some organizations require their use. See the List of Special Characters for Passwords.
"""


class Mystery(unittest.TestCase):
    GEN = generator(ciphers, -400, 138192812)

    def test_encode_decode(self):
        block = encode(STRING_BLOCK, SECRET, self.GEN)
        reveal = decode(block, SECRET, self.GEN)
        self.assertIsInstance(reveal, str)

    def test_sign_verify(self):
        password = os.environ.get("MISTYFY_PASSWORD_TEST") or ""
        encrypt = signs(password, secret=SECRET)
        verify = verify_signs(password, encrypt, secret=SECRET)
        self.assertTrue(verify is True, "Not True")


if __name__ == "__main__":
    unittest.main(verbosity=2)


