import os

addr_enc_stage1 = askAddress('Adddress of encrypted stage1', 'Enter Address')
stage1_size = askInt('Size of stage1', 'Enter Value')
dec_key = askInt('Decryption key of stage1', 'Enter Value')
g_output_dir = askDirectory('Select output folder', 'Select output folder')

def decrypt(buf, key):
    res = ''
    for ch in buf:
        key = (key * 0x343fd + 0x269ec3) & 0xffffffff
        res += chr((ch & 0xff) ^ ((key >> 0x10) & 0xff))
    return res

def main():
    print('[*] Address of encrypted stage1 : {}'.format(addr_enc_stage1))
    print('[*] Size of stage1              : {:08x}'.format(stage1_size))
    print('[*] Decryption key of stage1    : {:08x}'.format(dec_key))

    enc_stage1 = getBytes(addr_enc_stage1, stage1_size)
    stage1 = decrypt(enc_stage1, dec_key)

    fpath_dump = os.path.join(str(g_output_dir), 'stage1.bin')
    open(fpath_dump, 'wb').write(stage1)
    print('[+] Extracted stage1 to         : {}'.format(fpath_dump))

if __name__ == '__main__':
    main()