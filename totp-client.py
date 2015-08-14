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

'''TOTP Client

Stores TOTP secrets in system keyring and generates tokens based on them.
'''

import argparse
import base64
import hashlib
import hmac
import os
import time
import struct
import sys

import getpass
import keyring
import pylibscrypt


def store_key(name, key):
    keyring.set_password('totp-client', name, key)


def retrieve_key(name):
    return keyring.get_password('totp-client', name)


def delete_key(name):
    keyring.delete_password('totp-client', name)


def enc_key(key, pwd):
    salt = os.urandom(16)
    pad = bytearray(pylibscrypt.scrypt(pwd, salt, olen=len(key)))
    key = bytearray(key)
    for i, p in enumerate(pad):
        key[i] = key[i] ^ p
    return base64.b64encode(salt + bytes(key))


def dec_key(key, pwd):
    key = base64.b64decode(key)
    salt, key = key[:16], bytearray(key[16:])
    pad = bytearray(pylibscrypt.scrypt(pwd, salt, olen=len(key)))
    for i, p in enumerate(pad):
        key[i] = key[i] ^ p
    return key


def get_totp(key, digits=6):
    t = int(time.time() / 30)
    h = bytearray(hmac.new(key, struct.pack('>Q', t), hashlib.sha1).digest())
    o = h[19] & 0xf
    d = struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff
    return d % (10 ** digits)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('-n', '--new', action='store_true',
                        help='encrypt and store new TOTP secret in keyring')
    action.add_argument('-d', '--delete', action='store_true',
                        help='delete a TOTP secret from keyring')
    action.add_argument('-l', '--loop', action='store_true',
                        help=('loop producing new tokens every 30s until'
                                    ' interrupted'))
    parser.add_argument('USER', help='username for storing and retrieving')
    args = parser.parse_args()
    name = args.USER

    def die(m):
        sys.stderr.write(m + '\n')
        sys.exit(1)

    if args.new:
        if retrieve_key(name):
            die('A TOTP secret for "%s" already exists!' % name)
        key = getpass.getpass('TOTP key:')
        pwd = getpass.getpass('Encryption password:')
        e = enc_key(key, pwd)
        store_key(name, e)
        sys.exit()

    e = retrieve_key(name)
    if not e:
        die('A TOTP secret for "%s" not found!' % name)

    if args.delete:
        delete_key(name)
        sys.exit()

    pwd = getpass.getpass('Encryption password:')
    key = dec_key(e, pwd)
    while True:
        print(get_totp(key))
        if not args.loop:
            sys.exit()

        t = time.time()
        dt = int(t/30 + 1)*30 - t
        time.sleep(dt + 0.5)

