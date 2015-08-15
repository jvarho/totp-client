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

from __future__ import print_function

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


# defaults from the RFC and/or real world
hotp_hash = hashlib.sha1
hotp_length = 6
totp_timeout = 30


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


def get_totp(key):
    t = int(time.time() / totp_timeout)
    h = bytearray(hmac.new(key, struct.pack('>Q', t), hotp_hash).digest())
    o = h[19] & 0xf
    d = struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff
    return d % (10 ** hotp_length)


def die(m):
    sys.stderr.write(m + '\n')
    sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('-n', '--new', action='store_true',
                        help='encrypt and store new TOTP secret in keyring')
    action.add_argument('-d', '--delete', action='store_true',
                        help='delete a TOTP secret from keyring')
    action.add_argument('-l', '--loop', action='store_true',
                        help=('loop producing new tokens every 30s until'
                              ' interrupted'))
    parser.add_argument('--hash',
                        help=('the HOTP hash algorithm (default: sha1)'))
    parser.add_argument('--timeout',
                        help=('the TOTP timeout in seconds (default: 30)'))
    parser.add_argument('--digits',
                        help=('output length in digits (default: 6)'))
    parser.add_argument('USER', help='username for storing and retrieving')
    return parser.parse_args()


def op_new(name):
    if retrieve_key(name):
        die('A TOTP secret for "%s" already exists!' % name)
    key = getpass.getpass('TOTP key:')
    pwd = getpass.getpass('Encryption password:')
    e = enc_key(key, pwd)
    store_key(name, e)


def op_delete(name):
    e = retrieve_key(name)
    if not e:
        die('A TOTP secret for "%s" not found!' % name)
    delete_key(name)


def op_token(name, loop):
    e = retrieve_key(name)
    if not e:
        die('A TOTP secret for "%s" not found!' % name)

    pwd = getpass.getpass('Encryption password:')
    key = dec_key(e, pwd)
    while True:
        print(get_totp(key), end='')
        if not loop:
            print()
            break

        t = time.time()
        t0 = int(t / totp_timeout) * totp_timeout
        print('.'*(int(t-t0)//1), end='')
        sys.stdout.flush()
        t1 = t0 + totp_timeout
        while t < t1:
            time.sleep(min(1, t1 - t + 0.5))
            print('.', end='')
            sys.stdout.flush()
            t = time.time()
        print()


if __name__ == '__main__':
    args = parse_args()

    if args.hash:
        try:
            hashlib.new(args.hash)
        except ValueError:
            die(('Unsupported hash algorithm "%s"!\n'
                 'Supported algorithms include: %s.')
                % (args.hash, ', '.join(hashlib.algorithms)))
        hotp_hash = lambda:hashlib.new(args.hash)

    if args.timeout:
        try:
            totp_timeout = float(args.timeout)
            if totp_timeout <= 0:
                raise
        except:
            die('Timeout must be a positive number, not "%s"!' % args.timeout)

    if args.digits:
        try:
            hotp_length = int(args.digits)
            if hotp_length < 6 or hotp_length > 10:
                raise
        except:
            die('Digits must be between 6 and 10, not "%s"!' % args.digits)

    if args.new:
        op_new(args.USER)
    elif args.delete:
        op_delete(args.USER)
    else:
        op_token(args.USER, args.loop)

