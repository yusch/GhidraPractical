import __main__ as flatapi
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import ReturnParameterImpl
from ghidra.program.model.listing.Function.FunctionUpdateType import DYNAMIC_STORAGE_FORMAL_PARAMS
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.symbol.FlowType import UNCONDITIONAL_CALL, UNCONDITIONAL_JUMP
from ghidra.program.model.symbol.SourceType import USER_DEFINED


def get_winmain_address():
    current_program = flatapi.getCurrentProgram()
    entry = current_program.getSymbolTable().getSymbol('entry')
    
    '''
    entry:
        CALL 0x...
        JMP  0x...
    '''
    inst = flatapi.getInstructionAt(entry.getAddress())
    if inst.getFlowType() != UNCONDITIONAL_CALL:
        return
    
    next_inst = inst.getNext()
    if next_inst.getFlowType() != UNCONDITIONAL_JUMP:
        return

    image_base = current_program.getImageBase().getOffset()

    search_start_address = next_inst.getFlows()[0]
    search_end_address = search_start_address.add(0x200)
    search_range = AddressSet(search_start_address, search_end_address)
    
    '''
    PUSH 0x......00; <- ImageBase
    CALL
    '''
    hits = flatapi.findBytes(search_range, '\x68\x00.{3}\xe8', 0, 1)
    for hit_address in hits:
        inst_push = flatapi.getInstructionAt(hit_address)
        val = inst_push.getOpObjects(0)[0]
        '''
        PUSH IMAGE_BASE
        CALL WinMain
        '''
        if val.getClass() == Scalar and val.getValue() == image_base:
            inst_call = inst_push.getNext()
            if inst_call.getFlowType() == UNCONDITIONAL_CALL:
                return inst_call.getFlows()[0]


def apply_winmain_signature(address):
    func = flatapi.getFunctionAt(address)
    current_program = flatapi.getCurrentProgram()

    service = flatapi.getState().getTool().getService(DataTypeManagerService)
    dt_manager = filter(lambda x: x.getName() == 'windows_vs12_32', service.getDataTypeManagers())[0]
    
    dt_hinstance = dt_manager.getDataType('/WinDef.h/HINSTANCE')
    dt_lpstr = dt_manager.getDataType('/winnt.h/LPSTR')
    dt_int = dt_manager.getDataType('/int')

    ret_type = ReturnParameterImpl(dt_int, current_program)
    param1 = ParameterImpl('hInstance', dt_hinstance, current_program, USER_DEFINED)
    param2 = ParameterImpl('hPrevInstance', dt_hinstance, current_program, USER_DEFINED)
    param3 = ParameterImpl('lpCmdLine', dt_lpstr, current_program, USER_DEFINED)
    param4 = ParameterImpl('nShowCmd', dt_int, current_program, USER_DEFINED)
    
    func.updateFunction('__stdcall', ret_type, DYNAMIC_STORAGE_FORMAL_PARAMS, True, USER_DEFINED, param1, param2, param3, param4)


def main():
    winmain_address = get_winmain_address()
    if winmain_address:
        print('Found WinMain at {}'.format(winmain_address))
        flatapi.createLabel(winmain_address, 'WinMain', False)
        apply_winmain_signature(winmain_address)


if __name__ == '__main__':
    main()