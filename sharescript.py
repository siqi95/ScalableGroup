#!/usr/bin/python
import os, sys, argparse, tempfile, shutil
import secretsharing as sss

import jsonpickle  # install via  "$ sudo pip install -U jsonpickle"

from hashlib import sha256

from passlib.hash import pbkdf2_sha256, argon2, sha512_crypt, sha1_crypt

from random import randrange
import json

import base64
from Crypto.Cipher import AES
from Crypto import Random


def pxor(pwd, share):
    '''
      XOR a hashed password into a Shamir-share
      1st few chars of share are index, then "-" then hexdigits
      we'll return the same index, then "-" then xor(hexdigits,sha256(pwd))
      we truncate the sha256(pwd) to if the hexdigits are shorter
      we left pad the sha256(pwd) with zeros if the hexdigits are longer
      we left pad the output with zeros to the full length we xor'd
    '''
    words = share.split("-")
    hexshare = words[1]
    slen = len(hexshare)
    hashpwd = sha256(pwd).hexdigest()
    hlen = len(hashpwd)
    outlen = 0
    if slen < hlen:
        outlen = slen
        hashpwd = hashpwd[0:outlen]
    elif slen > hlen:
        outlen = slen
        hashpwd = hashpwd.zfill(outlen)
    else:
        outlen = hlen
    xorvalue = int(hexshare, 16) ^ int(hashpwd, 16)  # convert to integers and xor
    paddedresult = '{:x}'.format(xorvalue)  # convert back to hex
    paddedresult = paddedresult.zfill(outlen)  # pad left
    result = words[0] + "-" + paddedresult  # put index back
    return result


def newsecret(numbytes):
    '''
        let's get a number of pseudo-random bytes, as a hex string
    '''
    binsecret = open("/dev/urandom", "rb").read(numbytes)
    secret = binsecret.encode('hex')
    return secret


def pwds_to_shares(pwds, k, numbytes):
    '''
        Give a set of n passwords, and a threshold (k) generate a set
        of Shamir-like 'public' shares for those.
        We do this by picking a random secret, generating a set of
        Shamir-shares for that, then XORing a hashed password with
        each share.  Given the set of 'public' shares and k of the
        passwords, one can re-construct the secret.
        Note:  **There are no security guarantees for this**
        This is just done for a student programming exercise, and
        is not for real use. With guessable passwords, the secret
        can be re-constructed!
    '''
    n = len(pwds)  # we're in k-of-n mode...
    secret = newsecret(numbytes)  # generate random secret
    shares = sss.SecretSharer.split_secret(secret, k, n)  # split secret
    diffs = []  # diff the passwords and shares
    for i in range(0, n):
        diffs.append(pxor(pwds[i], shares[i]))
    return diffs


def pwds_shares_to_secret(kpwds, kinds, diffs):
    '''
        take k passwords, indices of those, and the "public" shares and
        recover shamir secret
    '''
    shares = []
    for i in range(0, len(kpwds)):
        shares.append(str(pxor(kpwds[i], diffs[kinds[i]])))
    secret = sss.SecretSharer.recover_secret(shares)
    return secret


unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def decrypt(ciphertext, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted


def encrypt(raw, key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


BLOCK_SIZE = 16

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

with open(sys.argv[1]) as broken, open(sys.argv[2], "w+") as outputFile, open(sys.argv[3]) as ballfile:
    cracked = map(lambda x: x.split(':'), broken.read().splitlines())
    ball = json.load(ballfile)
    hashes = ball["hashes"]
    shares = ball["shares"]
    kinds = []
    kpwds = []
    for hashpass in cracked:
        kinds.append(hashes.index(hashpass[0]))
        kpwds.append(hashpass[1])
    secret = pwds_shares_to_secret(kpwds, kinds, shares)
    nextlev = decrypt(ball["ciphertext"], secret.zfill(32).decode('hex'))
    print secret
    outputFile.write(str(nextlev))
