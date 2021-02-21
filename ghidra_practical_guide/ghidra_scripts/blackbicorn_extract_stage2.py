from collections import namedtuple
import os
import struct
from ghidra.app.emulator import EmulatorHelper

g_output_dir = 'C:\Ghidra\ch07'
END_ADDRESS = 0xffffffff
STACK_ADDRESS = 0xa00000
DECOMPRESSED_SIZE_ADDRESS = 0xb00000
COMPRESSED_ADDRESS = 0xe000000
DECOMPRESSED_ADDRESS = 0xf000000

def emulate_decompress(decompress_address, compressed_buf):
    emu = EmulatorHelper(currentProgram)

    end_address = toAddr(END_ADDRESS)
    stack_address = toAddr(STACK_ADDRESS)
    addr_compressed = toAddr(COMPRESSED_ADDRESS)
    compressed_size = len(compressed_buf)
    addr_decompressed = toAddr(DECOMPRESSED_ADDRESS)
    p_decompressed_size = toAddr(DECOMPRESSED_SIZE_ADDRESS)

    emu.writeRegister(emu.getStackPointerRegister(), stack_address.getOffset())
    emu.writeMemory(addr_compressed, compressed_buf)
    emu.writeMemoryValue(stack_address, 4, end_address.getOffset())
    emu.writeMemoryValue(stack_address.add(4), 4, addr_compressed.getOffset())
    emu.writeMemoryValue(stack_address.add(8), 4, compressed_size)
    emu.writeMemoryValue(stack_address.add(0xc), 4, addr_decompressed.getOffset())
    emu.writeMemoryValue(stack_address.add(0x10), 4, p_decompressed_size.getOffset())
    emu.writeRegister(emu.getPCRegister(), decompress_address.getOffset())

    while monitor.isCancelled() is False:
        current_address = emu.getExecutionAddress()
        if (current_address == end_address):
            break
        res = emu.step(monitor)

    decompressed_size = struct.unpack('<I', emu.readMemory(p_decompressed_size, 4).tostring())[0]
    decompressed_buf = emu.readMemory(addr_decompressed, decompressed_size)
    emu.dispose()
    return decompressed_buf.tostring()

def get_config_address():
    hits = findBytes(None, '\x89.{2}\x81.{4}\x00\x00', 0)
    if len(hits) != 1:
        print('[!] Failed to find code pattern of getting config')
        return
    inst_mov = getInstructionAt(hits[0])
    inst_add = inst_mov.getNext()
    config_address = toAddr(inst_add.getOpObjects(1)[0].getValue())
    return config_address

def get_config():
    config_address = get_config_address()
    if not config_address:
        return
    print('[*] Found config at {}'.format(config_address))
    Config = namedtuple('Config', 'size dec_key flag_compressed decompressed_size enc_stage2')
    size = getInt(config_address)
    dec_key = getInt(config_address.add(4)) & 0xffffffff
    flag_compressed = getByte(config_address.add(8))
    decompressed_size = getInt(config_address.add(9))
    enc_stage2 = getBytes(config_address.add(0xd), size)
    return Config(size, dec_key, flag_compressed, decompressed_size, enc_stage2)

def get_decompress_address():
    hits = findBytes(None, '\xe8.{4}\x83\xc4\x10\x8b.{2}\x89.{2}\xff', 0)
    if len(hits) != 1:
        print('[!] Failed to find code pattern of calling decompress function')
        return
    inst_call = getInstructionAt(hits[0])
    return inst_call.getFlows()[0]

def decrypt(buf, key):
    res = ''
    for ch in buf:
        key = (key * 0x343fd + 0x269ec3) & 0xffffffff
        res += chr((ch&0xff) ^ ((key >> 0x10) & 0xff))
    return res

def main():
    config = get_config()
    if not config:
        return
    stage2 = decrypt(config.enc_stage2, config.dec_key)
    if config.flag_compressed:
        decompress_address = get_decompress_address()
        if not decompress_address:
            return
        print('[*] Found decompress function at {}'.format(decompress_address))
        stage2 = emulate_decompress(decompress_address, stage2)
    fpath_dump = os.path.join(g_output_dir, 'stage2.bin')
    open(fpath_dump, 'wb').write(stage2)
    print('[+] Extracted stage2 to {}'.format(fpath_dump))

if __name__ == '__main__':
    main()