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

'''TOTP Class'''

from __future__ import print_function

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time

import pylibscrypt


class TOTP(object):

    def __init__(self, key, salt, h_length, h_hash, t_timeout, t_zero):
        self.key = key
        self.salt = salt
        self.h_length = h_length
        self.h_hash = h_hash
        self.t_timeout = t_timeout
        self.t_zero = t_zero

    def dec_key(self, pwd):
        pad = bytearray(pylibscrypt.scrypt(pwd, self.salt, olen=len(self.key)))
        for i, p in enumerate(pad):
            self.key[i] = self.key[i] ^ p

    def new_hash(self):
        return lambda:hashlib.new(self.h_hash)

    def token(self):
        t = struct.pack('>Q', int((time.time() - self.t_zero) / self.t_timeout))
        h = bytearray(hmac.new(self.key, t, self.new_hash()).digest())
        o = h[-1] & 0xf
        d = struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff
        d = d % (10 ** self.h_length)
        fmt = '%0' + ('%d' % self.h_length) + 'd'
        return fmt % d

    def wait(self):
        t = time.time() - self.t_zero
        t0 = int(t / self.t_timeout) * self.t_timeout
        print('.'*(int(t-t0)//1), end='')
        sys.stdout.flush()
        t1 = t0 + selt.t_timeout
        while t < t1:
            time.sleep(min(1, t1 - t + 0.5))
            print('.', end='')
            sys.stdout.flush()
            t = time.time() - self.t_zero

    def to_json(self, pwd):
        salt = base64.b16encode(os.urandom(16))
        pad = bytearray(pylibscrypt.scrypt(pwd, salt, olen=len(self.key)))
        key = bytearray(self.key)
        for i, p in enumerate(pad):
            key[i] = key[i] ^ p
        return json.dumps({
            'key': base64.b16encode(key),
            'salt': salt,
            'h_length': self.h_length,
            'h_hash': self.h_hash,
            't_timeout': self.t_timeout,
            't_zero': self.t_zero,
        })

    @staticmethod
    def from_json(j, pwd=None):
        d = json.loads(j)
        d['key'] = bytearray(base64.b16decode(d['key']))
        d['salt'] = d['salt'].encode('ascii')
        t = TOTP(**d)
        if pwd is not None:
            t.dec_key(pwd)
        return t

