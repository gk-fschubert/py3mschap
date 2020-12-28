#!/bin/env python3

from pprint import pformat
from pprint import pprint

DEBUK=True
def show(smt: str):
    global DEBUK
    if(DEBUK):
        print(smt)

def pshow(smt):
    show(pformat(smt))


def test_des():
    from py3mschap import des
    meth = des.DES(b"somesecr")
    txt = b"plaintext"
    enc = meth.encrypt(txt)

    show("des enc:")
    pshow(enc)
    dec = meth.decrypt(enc)

    show("des dec:")
    pshow(enc)
    if not txt.startswith(dec):
        return False

    return True

def test_md4():

    from py3mschap import md4
    h = md4.MD4()
    h.update("some1")
    h.update("some2")
    pshow(h.digest())

    return True


def test_mppe_rad1():
    from py3mschap import mppe

    show("mppe.radius_encrypt_keys:")
    enc = mppe.radius_encrypt_keys("sdfas", "radpass", "sadfsdfs", "sdfsd")
    pshow(enc)

    return True

def test_mppe_rad2():
    from py3mschap import mppe

    show("gen_radius_encrypt_keys:")
    user_pass = "sdfas"
    rad_pass = "radpass"
    secret = "sadfsdfs"
    rq_auth = "sdfsd"
    send_key, recv_key = mppe.gen_radius_encrypt_keys(user_pass, rad_pass, secret, rq_auth)

    show("send_key")
    pshow(send_key)
    show("recv_key")
    pshow(recv_key)

    return True

def test_mschap1():
    from py3mschap import mschap

def scream(msg: str):
    print()
    print("!!! - " + msg)
    print()


if __name__ == "__main__":
    # DEBUK = False

    print("\nDES tests")
    if not test_des(): scream("des failed")
    print("\nMD4 tests")
    if not test_md4(): scream("md4 failed")
    print("\nMPPE tests")
    if not test_mppe_rad1(): scream("rad1 failed")
    if not test_mppe_rad2(): scream("rad2 failed")
