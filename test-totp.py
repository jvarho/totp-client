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
    secret1 = '1234567890'*2
    #For the following cf. http://crypto.stackexchange.com/a/27499/13625
    secret256 = '1234567890'*3+'12'
    secret512 = '1234567890'*6+'1234'
    def _test_all(self, at, t1, t256, t512):
        self._test_vector(self.secret1, at, t1, h_length=8)
        self._test_vector(self.secret256, at, t256, h_length=8, h_hash='sha256')
        self._test_vector(self.secret512, at, t512, h_length=8, h_hash='sha512')

    def test_vectors_1(self):
        self._test_all(59, '94287082', '46119246', '90693936')

    def test_vectors_2(self):
        self._test_all(1111111109, '07081804', '68084774', '25091201')

    def test_vectors_3(self):
        self._test_all(1111111111, '14050471', '67062674', '99943326')

    def test_vectors_4(self):
        self._test_all(1234567890, '89005924', '91819424', '93441116')

    def test_vectors_5(self):
        self._test_all(2000000000, '69279037', '90698825', '38618901')

    def test_vectors_6(self):
        self._test_all(20000000000, '65353130', '77737706', '47863826')


class NewVectors(TOTPTest):
    '''Some random test vectors intended to test all parameters'''
    def test_vector_n1(self):
        self._test_vector('1234', 10, '110366')

    def test_vector_n2(self):
        self._test_vector('1234', 20, '110366')

    def test_vector_n3(self):
        self._test_vector('1234', 40, '336582')

    def test_vector_n4(self):
        self._test_vector('1234', 10, '8110366', h_length=7)

    def test_vector_n5(self):
        self._test_vector('1234', 10, '18110366', h_length=8)

    def test_vector_n6(self):
        self._test_vector('1234', 10, '127174', h_hash='sha256')

    def test_vector_n7(self):
        self._test_vector('1234', 10, '637043', h_hash='sha512')

    def test_vector_n8(self):
        self._test_vector('1234', 100, '110366', t_zero=90)

    def test_vector_n9(self):
        self._test_vector('1234', 40, '110366', t_timeout=60)

    def test_vector_n10(self):
        self._test_vector('1234', 100, '336582', t_timeout=60)

    def test_vector_p1(self):
        self._test_vector('asdf', 10, '036575', pwd='qwerty', salt='1234')

    def test_vector_p2(self):
        self._test_vector('asdf', 20, '036575', pwd='qwerty', salt='1234')

    def test_vector_p3(self):
        self._test_vector('asdf', 40, '865509', pwd='qwerty', salt='1234')

    def test_vector_p4(self):
        self._test_vector('asdfg', 10, '015311', pwd='qwerty', salt='1234')

    def test_vector_p5(self):
        self._test_vector('asdf', 10, '986141', pwd='qwertyu', salt='1234')

    def test_vector_p6(self):
        self._test_vector('asdf', 10, '490784', pwd='qwerty', salt='12345')


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(RFCVectors))
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(NewVectors))
    unittest.TextTestRunner().run(suite)
