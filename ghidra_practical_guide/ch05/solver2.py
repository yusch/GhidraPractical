#!/usr/bin/env python3
# encoding: UTF-8

import base64

def custom_b64decode(s, custom_table):
    s = s.translate(str.maketrans(custom_table, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'))
    return base64.b64decode(s)

print(custom_b64decode('4PpnRoanRomTze4SKPo+Zwd3IejS', 'b9V12dPGtk7BKZUD/NJeX4vxjIcERzH+pQgT5iwYAlMyCWOFfnr3Soq06L8hamsu'))
