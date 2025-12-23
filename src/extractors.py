from pathlib import Path
from typing import List, Dict, Tuple, Set

from utils import compute_file_hashes, get_file_type_info

import idapro
import idaapi
import ida_funcs
import ida_xref
import ida_nalt
import idautils
import idc

def extract_imports() -> List[dict]:

    imports = []

    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "unknown"
        
        def import_callback(ea, name, ordinal):
            if name:
                imports.append({
                    'name': name,
                    'address': f'0x{ea:x}',
                    'library': module_name
                })
            return 1

        ida_nalt.enum_import_names(i, import_callback)

    return imports


def extract_exports() -> List[dict]:

    exports = []

    for index, ordinal, ea, name in idautils.Entries():
        exports.append({
            'name': name,
            'address': f'0x{ea:x}',
            'ordinal': ordinal
        })

    return exports


def extract_binary_info(file_path: str) -> dict:
    
    path = Path(file_path)
    file_size = path.stat().st_size if path.exists() else 0

    return {
        'name': path.name,
        'file_path': str(path.absolute()),
        'file_size': file_size,
        'file_type': get_file_type_info(),
        'hashes': compute_file_hashes(file_path) if path.exists() else {},
    }

def extract_functions() -> Tuple[List[dict], Dict[int, str]]:

    if not idautils or not idaapi:
        return [], {}

    functions = []
    address_to_name = {}

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = ida_funcs.get_func_name(func_ea)
        func_size = func.end_ea - func.start_ea
        address_to_name[func_ea] = func_name

        functions.append({
            'name': func_name,
            'address': f'0x{func_ea:x}',
            'size': func_size,
        })

    return functions, address_to_name


def determine_string_type(value: str) -> str:
    try:
        value.encode('ascii')
        return 'ascii'
    except UnicodeEncodeError:
        return 'unicode'


def extract_strings(min_length: int = 4) -> List[dict]:
    if not idautils:
        return []

    strings = []
    seen_values: Set[str] = set()

    for s in idautils.Strings():
        if len(str(s)) < min_length:
            continue

        value = str(s)
        if value in seen_values:
            continue
        seen_values.add(value)

        strings.append({
            'value': value,
            'address': f'0x{s.ea:x}',
            'length': len(str(s)),
            'type': determine_string_type(value)
        })

    return strings
def is_call_instruction(head_ea: int) -> bool:

    mnem = idc.print_insn_mnem(head_ea)
    call_mnemonics = ['call', 'bl', 'blr', 'jal', 'jalr', 'jmp', 'b', 'j']
    return mnem and mnem.lower() in call_mnemonics

def get_function_start(target_ea: int) -> int:
    if not idaapi:
        return target_ea

    target_func = ida_funcs.get_func(target_ea)
    if target_func:
        return target_func.start_ea
    return target_ea


def is_tail_call_jmp(head_ea: int, target_ea: int, func_starts: Set[int], import_map: Dict[int, str]) -> bool:
    mnem = idc.print_insn_mnem(head_ea)
    if not mnem or mnem.lower() not in ['jmp', 'b', 'j']:
        return False

    target_func_start = get_function_start(target_ea)

    if target_func_start in func_starts or target_ea in import_map or target_func_start in import_map:
        return True

    return False


def determine_call_type(head_ea: int, xref_type: int) -> str:

    if not ida_xref or not idc:
        return 'direct'

    try:
        # Get instruction mnemonic and operands
        mnem = idc.print_insn_mnem(head_ea)
        op_type = idc.get_operand_type(head_ea, 0)

        # Check for indirect call (through register or memory)
        # o_reg = 1 (register), o_phrase = 3 (base+index), o_displ = 4 (base+index+disp), o_mem = 2 (direct memory)
        if op_type in [1, 2, 3, 4]:  # Register or memory operand
            return 'indirect'

        # Check for tail call (call followed by ret)
        next_ea = idc.next_head(head_ea)
        if next_ea != idc.BADADDR:
            next_mnem = idc.print_insn_mnem(next_ea)
            if next_mnem and next_mnem.lower() in ['ret', 'retn', 'retf']:
                return 'tail'

        # Default to direct call
        return 'direct'

    except Exception:
        return 'direct'


def extract_calls(address_to_name: Dict[int, str], imports: List[dict] = None) -> List[dict]:

    calls = []
    seen_calls: Set[Tuple[int, int]] = set()
    func_starts = set(address_to_name.keys())

    # Build import address mapping
    import_map = {}
    if imports:
        for imp in imports:
            try:
                addr = int(imp['address'], 16)
                import_map[addr] = imp['name']
            except (ValueError, KeyError):
                continue

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        for head_ea in idautils.Heads(func.start_ea, func.end_ea):
            try:
                mnem = idc.print_insn_mnem(head_ea)
                if not mnem:
                    continue

                for xref in idautils.XrefsFrom(head_ea, 0):
                    target_ea = xref.to
                    target_func_start = get_function_start(target_ea)

                    is_internal = target_func_start in func_starts
                    is_import = target_ea in import_map or target_func_start in import_map

                    if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                        if not is_call_instruction(head_ea):
                            continue

                        if mnem.lower() in ['jmp', 'b', 'j']:
                            if not is_tail_call_jmp(head_ea, target_ea, func_starts, import_map):
                                continue

                        if not is_internal and not is_import:
                            continue

                        to_addr = target_func_start if is_internal else target_ea
                        call_key = (func_ea, to_addr)

                        if call_key in seen_calls:
                            continue
                        seen_calls.add(call_key)

                        calls.append({
                            'from_address': f'0x{func_ea:x}',
                            'to_address': f'0x{to_addr:x}',
                            'offset': f'0x{head_ea:x}',
                            'type': determine_call_type(head_ea, xref.type)
                        })

                    elif xref.type in [ida_xref.dr_O, ida_xref.dr_R]:
                        if not is_internal:
                            continue

                        if mnem.lower() not in ['lea', 'mov', 'adr', 'adrp', 'ldr']:
                            continue

                        to_addr = target_func_start
                        call_key = (func_ea, to_addr)

                        if call_key in seen_calls:
                            continue
                        seen_calls.add(call_key)

                        calls.append({
                            'from_address': f'0x{func_ea:x}',
                            'to_address': f'0x{to_addr:x}',
                            'offset': f'0x{head_ea:x}',
                            'type': 'callback'
                        })

            except Exception:
                continue

    return calls
