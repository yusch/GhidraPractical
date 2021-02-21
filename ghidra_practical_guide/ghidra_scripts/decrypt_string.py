from javax.crypto.spec import SecretKeySpec
from javax.crypto import Cipher

from ghidra.app.util import NamespaceUtils

# padding for DS key
padding = lambda s: s + (8 - len(s) % 8) * '\x00'


def set_comment(addr, text):
    cu = currentProgram.getListing().getCodeUnitAt(addr)
    cu.setComment(cu.EOL_COMMENT, text)

def get_xrefs(addr, ref_types=['UNCONDITIONAL_CALL']):
    xrefs = []
    for xref in getReferencesTo(addr):
        if xref.getReferenceType().toString() in ref_types:
            xrefs.append(xref.getFromAddress())
    return xrefs

def get_caller_addrs_of_symbol(symbol):
    xrefs = []
    for sym in NamespaceUtils.getSymbols(symbol, currentProgram):
        xrefs.extend(get_xrefs(sym.getAddress()))
    return xrefs

def parse_java_string_at(data_addr):
    length = getBytes(data_addr, 1)[0]
    string = getBytes(data_addr.add(1), length).tostring()
    return string

def decrypt_des(key, enc):
    des = Cipher.getInstance('DES')
    ks = SecretKeySpec(padding(key), 'DES')
    des.init(Cipher.DECRYPT_MODE, ks)
    return ''.join([chr(b) for b in des.doFinal(enc)])

def get_jutils_ctor():
    for get_instance_caller_addr in get_caller_addrs_of_symbol('javax::crypto::Cipher::getInstance'):
        op_const_string_for_alg = getInstructionBefore(get_instance_caller_addr)
        js = parse_java_string_at(op_const_string_for_alg.getAddress(1))
        if js == 'DES':
            return getFunctionContaining(op_const_string_for_alg.getAddress())

def run():
    jutils_ctor = get_jutils_ctor()
    jutil_ctor_caller_addrs = get_xrefs(jutils_ctor.getEntryPoint())

    # iterate JUtils ctor's caller functions
    for jutil_ctor_caller_addr in jutil_ctor_caller_addrs:
        # check if caller's name is not same as ctor
        if jutils_ctor.toString() != getFunctionContaining(jutil_ctor_caller_addr).toString():

            # get key string
            op_const_str_for_key = getInstructionBefore(jutil_ctor_caller_addr)
            key = parse_java_string_at(op_const_str_for_key.getAddress(1))

            # get encrypted hex string
            op_const_str_for_enc = getInstructionAfter(jutil_ctor_caller_addr)
            enc = parse_java_string_at(op_const_str_for_enc.getAddress(1))

            print('[*] key: {}'.format(key))
            print('[*] enc: {}'.format(enc))
            
            # decrypt by DES
            dec = decrypt_des(key, enc.decode('hex'))
            print('[*] decrypted: {}'.format(dec))

            # add EOL comment
            set_comment(op_const_str_for_enc.getAddress(), dec)
            print('[*] added comment at {}'.format(op_const_str_for_enc.getAddress()))
            print('')

run()