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

'''TOTP-Client

Stores TOTP secrets in system keyring and generates tokens based on them.
'''

from __future__ import print_function

import argparse
import hashlib
import hmac
import time
import struct
import sys

import getpass
import keyring

from totp import TOTP


__version__ = '0.1.0'


def store_key(name, key):
    keyring.set_password('totp-client', name, key)


def retrieve_key(name):
    return keyring.get_password('totp-client', name)


def delete_key(name):
    keyring.delete_password('totp-client', name)


def get_pass(msg):
    pwd = getpass.getpass(msg)
    try:
        return pwd.decode(sys.stdin.encoding).encode('utf8')
    except AttributeError:
        return bytes(pwd, 'utf8')


def die(m):
    sys.stderr.write(m + '\n')
    sys.exit(1)


def parse_args():
    description = __doc__.split('\n')[2]
    parser = argparse.ArgumentParser('TOTP-Client', description=description)
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s ' + __version__,
                        help=argparse.SUPPRESS)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('-n', '--new', action='store_true',
                        help='encrypt and store new TOTP secret in keyring')
    action.add_argument('-d', '--delete', action='store_true',
                        help='delete a TOTP secret from keyring')
    action.add_argument('-l', '--loop', action='store_true',
                        help=('produce new tokens as they expire, until'
                              ' interrupted'))
    modifiers = parser.add_argument_group(
        description='The following arguments modify the TOTP/HOTP parameters.'
        ' The defaults work for gauth compatible use.'
        ' Parameter options used with --new are stored.'
        ' Parameter options used when generating tokens override them.'
    )
    modifiers.add_argument('--hash',
                        help='the HOTP hash algorithm (default: sha1)')
    modifiers.add_argument('--timeout',
                        help='the TOTP timeout in seconds (default: 30)')
    modifiers.add_argument('--digits',
                        help='token length in digits (default: 6)')
    modifiers.add_argument('--zero',
                        help='time to start counting from (default: 0)')
    parser.add_argument('USER', help='username for the secret (required)')
    return parser.parse_args()


def op_new(name, modifiers):
    if retrieve_key(name):
        die('A TOTP secret for "%s" already exists!' % name)
    key = get_pass('TOTP key:')
    pwd = get_pass('Encryption password:')
    t = TOTP(key, salt=None, **modififers)
    e = t.to_json(pwd)
    store_key(name, e)


def op_delete(name):
    e = retrieve_key(name)
    if not e:
        die('A TOTP secret for "%s" not found!' % name)
    delete_key(name)


def op_token(name, loop, modifiers):
    e = retrieve_key(name)
    if not e:
        die('A TOTP secret for "%s" not found!' % name)

    pwd = get_pass('Encryption password:')
    t = TOTP.from_json(e, pwd, **modifiers)
    while True:
        print(t.token(), end='')
        if not loop:
            print()
            break

        t.wait()
        print()


if __name__ == '__main__':
    args = parse_args()

    modifiers = {}

    if args.hash:
        try:
            hashlib.new(args.hash)
        except ValueError:
            die(('Unsupported hash algorithm "%s"!\n'
                 'Supported algorithms include: %s.')
                % (args.hash, ', '.join(hashlib.algorithms)))
        modifiers['h_hash'] = args.hash

    if args.timeout:
        try:
            totp_timeout = float(args.timeout)
            if totp_timeout <= 0:
                raise
            modifiers['t_timeout'] = totp_timeout
        except:
            die('Timeout must be a positive number, not "%s"!' % args.timeout)

    if args.digits:
        try:
            hotp_length = int(args.digits)
            if hotp_length < 6 or hotp_length > 8:
                raise
            modifiers['h_length'] = hotp_length
        except:
            die('Digits must be between 6 and 8, not "%s"!' % args.digits)

    if args.zero:
        try:
            totp_zero = float(args.zero)
            if totp_zero < 0 or totp_zero > time.time():
                raise
            modifiers['t_zero'] = totp_zero
        except:
            die('Zero must be seconds of UNIX time from the epoch, not "%s"!'
                % args.zero)

    if args.new:
        op_new(args.USER, modifiers)
    elif args.delete:
        op_delete(args.USER)
    else:
        op_token(args.USER, args.loop, modifiers)

