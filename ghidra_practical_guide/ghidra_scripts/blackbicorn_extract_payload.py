from collections import namedtuple
import os
import struct
from ghidra.app.emulator import EmulatorHelper
from ghidra.feature.fid.service import FidService
from ghidra.util.NumericUtilities import parseHexLong

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
    Config = namedtuple('Config', 'flag_compressed compressed_size payload_size payload')
    flag_compressed = getByte(config_address.add(1)) & 0xff
    compressed_size = getInt(config_address.add(2))
    payload_size = getInt(config_address.add(6))
    payload = getBytes(config_address.add(0x26), compressed_size)
    return Config(flag_compressed, compressed_size, payload_size, payload)

def get_decompress_address():
    fid_service = FidService()
    # Function ID (Full Hash) of decompress function
    decompress_full_hash = parseHexLong('932243d3df1b21eb')
    func_manager = currentProgram.getFunctionManager()
    funcs = func_manager.getFunctions(True)
    for func in funcs:
        fid = fid_service.hashFunction(func)
        if fid and fid.getFullHash() == decompress_full_hash:
            return func.getEntryPoint()
    print('[!] Failed to find address of decompress function')

def main():
    config = get_config()
    if not config:
        return
    if config.flag_compressed:
        decompress_address = get_decompress_address()
        if not decompress_address:
            return
        print('[*] Found decompress function at {}'.format(decompress_address))
        payload = emulate_decompress(decompress_address, config.payload)
    else:
        payload = config.payload
    fpath_dump = os.path.join(g_output_dir, 'payload.bin')
    open(fpath_dump, 'wb').write(payload)
    print('[+] Extracted payload to {}'.format(fpath_dump))

if __name__ == '__main__':
    main()