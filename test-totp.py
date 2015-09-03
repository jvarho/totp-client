#!/usr/bin/env python

# Copyright (c) 2015, Jan Varho
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

'''Unit tests for totp.py'''

import unittest

import totp
import time


class TOTPTest(unittest.TestCase):
    def _test_vector(self, secret, at, token, pwd=None, **kwargs):
        t = totp.TOTP(secret, **kwargs)
        if pwd is not None:
            t.dec_key(pwd)
        tmp = time.time
        try:
            time.time = lambda:at
            o = t.token()
        finally:
            time.time = tmp
        self.assertEqual(token, o)


class RFCVectors(TOTPTest):
    '''From RFC 6238 Appendix B'''
    secret1 = b'1234567890'*2
    #For the following cf. http://crypto.stackexchange.com/a/27499/13625
    secret256 = b'1234567890'*3+b'12'
    secret512 = b'1234567890'*6+b'1234'
    def _test_all(self, at, t1, t256, t512):
        self._test_vector(self.secret1, at, t1, h_length=8)
        self._test_vector(self.secret256, at, t256, h_length=8, h_hash='sha256')
        self._test_vector(self.secret512, at, t512, h_length=8, h_hash='sha512')

    def test_vectors_1(self):
        self._test_all(59, b'94287082', b'46119246', b'90693936')

    def test_vectors_2(self):
        self._test_all(1111111109, b'07081804', b'68084774', b'25091201')

    def test_vectors_3(self):
        self._test_all(1111111111, b'14050471', b'67062674', b'99943326')

    def test_vectors_4(self):
        self._test_all(1234567890, b'89005924', b'91819424', b'93441116')

    def test_vectors_5(self):
        self._test_all(2000000000, b'69279037', b'90698825', b'38618901')

    def test_vectors_6(self):
        self._test_all(20000000000, b'65353130', b'77737706', b'47863826')


class NewVectors(TOTPTest):
    '''Some random test vectors intended to test all parameters'''
    def test_vector_n1(self):
        self._test_vector(b'1234', 10, b'110366')

    def test_vector_n2(self):
        self._test_vector(b'1234', 20, b'110366')

    def test_vector_n3(self):
        self._test_vector(b'1234', 40, b'336582')

    def test_vector_n4(self):
        self._test_vector(b'1234', 10, b'8110366', h_length=7)

    def test_vector_n5(self):
        self._test_vector(b'1234', 10, b'18110366', h_length=8)

    def test_vector_n6(self):
        self._test_vector(b'1234', 10, b'127174', h_hash='sha256')

    def test_vector_n7(self):
        self._test_vector(b'1234', 10, b'637043', h_hash='sha512')

    def test_vector_n8(self):
        self._test_vector(b'1234', 100, b'110366', t_zero=90)

    def test_vector_n9(self):
        self._test_vector(b'1234', 40, b'110366', t_timeout=60)

    def test_vector_n10(self):
        self._test_vector(b'1234', 100, b'336582', t_timeout=60)

    def test_vector_p1(self):
        self._test_vector(b'asdf', 10, b'036575', pwd=b'qwerty', salt=b'1234')

    def test_vector_p2(self):
        self._test_vector(b'asdf', 20, b'036575', pwd=b'qwerty', salt=b'1234')

    def test_vector_p3(self):
        self._test_vector(b'asdf', 40, b'865509', pwd=b'qwerty', salt=b'1234')

    def test_vector_p4(self):
        self._test_vector(b'asdfg', 10, b'015311', pwd=b'qwerty', salt=b'1234')

    def test_vector_p5(self):
        self._test_vector(b'asdf', 10, b'986141', pwd=b'qwertyu', salt=b'1234')

    def test_vector_p6(self):
        self._test_vector(b'asdf', 10, b'490784', pwd=b'qwerty', salt=b'12345')


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(RFCVectors))
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(NewVectors))
    unittest.TextTestRunner().run(suite)
