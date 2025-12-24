# IDA Export for AI Analysis
# IDAPython script to export decompiled functions, strings, memory, imports and exports for AI analysis

import os
import sys
import argparse
import idapro
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import idautils
import idc
import idaapi
import ida_auto

def get_idb_directory():
    """Get the directory where IDB file is located"""
    try:
        idb_path = ida_nalt.get_input_file_path()
        if not idb_path:
            import ida_loader
            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        return os.path.dirname(idb_path) if idb_path else os.getcwd()
    except:
        return os.getcwd()

def get_binary_path():
    """Get the currently loaded binary file path"""
    try:
        return ida_nalt.get_input_file_path()
    except:
        return None



def ensure_dir(path):
    """Ensure directory exists"""
    if not os.path.exists(path):
        os.makedirs(path)

def get_callers(func_ea):
    """Get list of addresses that call the current function"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))

def get_callees(func_ea):
    """Get list of function addresses called by the current function"""
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees
    
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))

def format_address_list(addr_list):
    """Format address list as comma-separated hexadecimal string"""
    return ", ".join([hex(addr) for addr in addr_list])

def export_decompiled_functions(export_dir):
    """Export decompiled code for all functions"""
    decompile_dir = os.path.join(export_dir, "decompile")
    ensure_dir(decompile_dir)
    
    total_funcs = 0
    exported_funcs = 0
    failed_funcs = []
    
    for func_ea in idautils.Functions():
        total_funcs += 1
        func_name = idc.get_func_name(func_ea)
        
        try:
            dec_obj = ida_hexrays.decompile(func_ea)
            if dec_obj is None:
                failed_funcs.append((func_ea, func_name, "decompile returned None"))
                continue
            
            dec_str = str(dec_obj)
            callers = get_callers(func_ea)
            callees = get_callees(func_ea)
            
            output_lines = []
            output_lines.append("/*")
            output_lines.append(" * func-name: {}".format(func_name))
            output_lines.append(" * func-address: {}".format(hex(func_ea)))
            output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
            output_lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
            output_lines.append(" */")
            output_lines.append("")
            output_lines.append(dec_str)
            
            output_filename = "{}.c".format(hex(func_ea))
            output_path = os.path.join(decompile_dir, output_filename)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            
            exported_funcs += 1
            
            if exported_funcs % 100 == 0:
                print("[+] Exported {} functions...".format(exported_funcs))
                
        except Exception as e:
            failed_funcs.append((func_ea, func_name, str(e)))
            continue
    
    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Failed: {}".format(len(failed_funcs)))
    
    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, 'w', encoding='utf-8') as f:
            for addr, name, reason in failed_funcs:
                f.write("{} {} - {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

def export_strings(export_dir):
    """Export all strings"""
    strings_path = os.path.join(export_dir, "strings.txt")
    
    string_count = 0
    with open(strings_path, 'w', encoding='utf-8') as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")
        
        for s in idautils.Strings():
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"
                
                f.write("{} | {} | {} | {}\n".format(
                    hex(s.ea),
                    s.length,
                    str_type,
                    string_content.replace('\n', '\\n').replace('\r', '\\r')
                ))
                string_count += 1
            except Exception as e:
                continue
    
    print("[*] Strings Summary:")
    print("    Total strings exported: {}".format(string_count))

def export_imports(export_dir):
    """Export import table"""
    imports_path = os.path.join(export_dir, "imports.txt")
    
    import_count = 0
    with open(imports_path, 'w', encoding='utf-8') as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            
            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True
            
            ida_nalt.enum_import_names(i, imp_cb)
    
    print("[*] Imports Summary:")
    print("    Total imports exported: {}".format(import_count))

def export_exports(export_dir):
    """Export export table"""
    exports_path = os.path.join(export_dir, "exports.txt")
    
    export_count = 0
    with open(exports_path, 'w', encoding='utf-8') as f:
        f.write("# Exports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            
            if name:
                f.write("{}:{}\n".format(hex(ea), name))
            else:
                f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
            export_count += 1
    
    print("[*] Exports Summary:")
    print("    Total exports exported: {}".format(export_count))

def export_memory(export_dir):
    """Export memory data in 1MB chunks, hexdump format"""
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)
    
    CHUNK_SIZE = 1 * 1024 * 1024  # 1MB
    BYTES_PER_LINE = 16
    
    total_bytes = 0
    file_count = 0
    
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        
        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)
        
        print("[*] Processing segment: {} ({} - {})".format(
            seg_name, hex(seg_start), hex(seg_end)))
        
        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)
            
            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end)))
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")
                
                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            if byte_val is not None:
                                line_bytes.append(byte_val)
                            else:
                                line_bytes.append(0)
                        else:
                            break
                    
                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue
                    
                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining
                    
                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."
                    
                    f.write("{:016X} | {} | {}\n".format(addr, hex_part.ljust(49), ascii_part))
                    
                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)
            
            file_count += 1
            current_addr = chunk_end
    
    print("\n[*] Memory Export Summary:")
    print("    Total bytes exported: {} ({:.2f} MB)".format(total_bytes, total_bytes / (1024*1024)))
    print("    Files created: {}".format(file_count))

def parse_arguments():

    """Parse command line arguments"""

    parser = argparse.ArgumentParser(

        description="IDA Export for AI Analysis - Export decompiled functions, strings, memory, imports and exports for AI analysis",

        formatter_class=argparse.RawDescriptionHelpFormatter,

        epilog="""

Usage examples:

  python ida_export.py binary.exe                    # Analyze specified binary file

  python ida_export.py binary.exe -o /path/to/output # Specify output directory

  python ida_export.py binary.exe --no-decompile     # Skip decompilation export

  python ida_export.py binary.exe --no-memory        # Skip memory data export

  python ida_export.py binary.exe --strings-only     # Export strings only

  python ida_export.py --help                        # Show help information



Features:

  - Export decompiled code for all functions (requires Hex-Rays plugin)

  - Export all strings (ASCII/UTF-16/UTF-32)

  - Export import and export tables

  - Export memory data (1MB chunked hexdump format)

  - Record function call relationships (callers and callees)

        """)

    

    parser.add_argument("binary", nargs="?",

                       help="Path to binary file to analyze (optional if running in IDA)")

    

    parser.add_argument("-o", "--output", 

                       help="Output directory path (default: export-for-ai folder in binary directory)")

    

    parser.add_argument("--no-decompile", action="store_true",

                       help="Skip decompilation export (skip Hex-Rays decompilation)")

    

    parser.add_argument("--no-memory", action="store_true",

                       help="Skip memory data export (skip memory dump)")

    

    parser.add_argument("--strings-only", action="store_true",

                       help="Export strings only, skip all other content")

    

    parser.add_argument("--no-strings", action="store_true",

                       help="Skip strings export")

    

    parser.add_argument("--no-imports", action="store_true",

                       help="Skip import table export")

    

    parser.add_argument("--no-exports", action="store_true",

                       help="Skip export table export")

    

    parser.add_argument("--verbose", "-v", action="store_true",

                       help="Show verbose output information")

    

    return parser.parse_args()
def run_headless_analysis(binary_path: str, export_dir: str, args) -> dict:
    """Run analysis in headless mode using idapro"""
    
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary file not found: {binary_path}")
    
    print(f'Opening database: {binary_path}')
    idapro.open_database(binary_path, True)
    
    print('Waiting for auto-analysis to complete...')
    ida_auto.auto_wait()
    
    # Check Hex-Rays plugin
    has_hexrays = False
    if not args.no_decompile and not args.strings_only:
        if not ida_hexrays.init_hexrays_plugin():
            print("[!] Hex-Rays decompiler is not available!")
            print("[!] Decompilation will be skipped.")
            has_hexrays = False
        else:
            has_hexrays = True
            print("[+] Hex-Rays decompiler initialized")
    
    print("")
    
    # Export strings
    if not args.strings_only and not args.no_strings:
        print("[*] Exporting strings...")
        export_strings(export_dir)
        print("")
    elif args.strings_only:
        print("[*] Strings only mode - exporting strings...")
        export_strings(export_dir)
        print("")
        idapro.close_database()
        return {"status": "completed"}
    
    # Export import table
    if not args.no_imports:
        print("[*] Exporting imports...")
        export_imports(export_dir)
        print("")
    
    # Export export table
    if not args.no_exports:
        print("[*] Exporting exports...")
        export_exports(export_dir)
        print("")
    
    # Export memory data
    if not args.no_memory:
        print("[*] Exporting memory...")
        export_memory(export_dir)
        print("")
    
    # Export decompiled code
    if has_hexrays and not args.no_decompile:
        print("[*] Exporting decompiled functions...")
        export_decompiled_functions(export_dir)
    
    idapro.close_database()
    return {"status": "completed"}


def main():
    """Main function"""
    try:
        args = parse_arguments()
    except:
        # If running in IDA, argument parsing may fail, use default settings
        class DefaultArgs:
            def __init__(self):
                self.binary = None
                self.output = None
                self.no_decompile = False
                self.no_memory = False
                self.strings_only = False
                self.no_strings = False
                self.no_imports = False
                self.no_exports = False
                self.verbose = False
        args = DefaultArgs()
    
    print("=" * 60)
    print("IDA Export for AI Analysis")
    print("=" * 60)
    
    # Check if running in IDA environment
    is_in_ida = False
    try:
        # Try to get currently loaded file
        current_binary = get_binary_path()
        if current_binary:
            is_in_ida = True
            print("[+] Running in IDA environment")
            print("[+] Current binary: {}".format(current_binary))
    except:
        pass
    
    # Handle binary file path
    binary_path = None
    if args.binary:
        binary_path = os.path.abspath(args.binary)
        if not os.path.exists(binary_path):
            print("[!] Error: Binary file not found: {}".format(binary_path))
            return 1
        print("[+] Binary to analyze: {}".format(binary_path))
    elif is_in_ida:
        # Running in IDA, use currently loaded file
        binary_path = current_binary
    else:
        print("[!] Error: No binary file specified")
        print("[!] Please specify a binary file path or run this script within IDA")
        print("[!] Use --help for usage information")
        return 1
    
    # Set output directory
    if args.output:
        export_dir = args.output
    else:
        # Use binary file directory
        if binary_path:
            export_dir = os.path.join(os.path.dirname(binary_path), "export-for-ai")
        else:
            idb_dir = get_idb_directory()
            export_dir = os.path.join(idb_dir, "export-for-ai")
    
    ensure_dir(export_dir)
    print("[+] Export directory: {}".format(export_dir))
    
    if args.verbose:
        print("[+] Settings:")
        print("    - Binary: {}".format(binary_path))
        print("    - Headless mode: {}".format("No" if is_in_ida else "Yes"))
        print("    - Memory: {}".format("No" if args.no_memory else "Yes"))
        print("    - Strings: {}".format("No" if args.no_strings else "Yes"))
        print("    - Imports: {}".format("No" if args.no_imports else "Yes"))
        print("    - Exports: {}".format("No" if args.no_exports else "Yes"))
        if args.strings_only:
            print("    - Mode: Strings only")
    
    print("")
    
    try:
        if is_in_ida:
            # Running in IDA GUI mode
            # Check Hex-Rays plugin
            has_hexrays = False
            if not args.no_decompile and not args.strings_only:
                try:
                    if not ida_hexrays.init_hexrays_plugin():
                        print("[!] Hex-Rays decompiler is not available!")
                        print("[!] Decompilation will be skipped.")
                        has_hexrays = False
                    else:
                        has_hexrays = True
                        print("[+] Hex-Rays decompiler initialized")
                except:
                    print("[!] Hex-Rays plugin check failed - may not be in IDA environment")
                    has_hexrays = False
            
            # Export strings
            if not args.strings_only and not args.no_strings:
                print("[*] Exporting strings...")
                export_strings(export_dir)
                print("")
            elif args.strings_only:
                print("[*] Strings only mode - exporting strings...")
                export_strings(export_dir)
                print("")
                print("=" * 60)
                print("[+] Export completed!")
                print("    Output directory: {}".format(export_dir))
                print("=" * 60)
                return 0
            
            # Export import table
            if not args.no_imports:
                print("[*] Exporting imports...")
                export_imports(export_dir)
                print("")
            
            # Export export table
            if not args.no_exports:
                print("[*] Exporting exports...")
                export_exports(export_dir)
                print("")
            
            # Export memory data
            if not args.no_memory:
                print("[*] Exporting memory...")
                export_memory(export_dir)
                print("")
            
            # Export decompiled code
            if has_hexrays and not args.no_decompile:
                print("[*] Exporting decompiled functions...")
                export_decompiled_functions(export_dir)
        else:
            # Running in headless mode
            print("[*] Running in headless mode...")
            result = run_headless_analysis(binary_path, export_dir, args)
            if result.get("status") != "completed":
                return 1
    
        print("")
        print("=" * 60)
        print("[+] Export completed!")
        print("    Output directory: {}".format(export_dir))
        print("=" * 60)
        return 0
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        if not is_in_ida:
            try:
                idapro.close_database()
            except:
                pass
        return 1

if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            sys.exit(0)
        sys.exit(main())
    except Exception as e:
        print("Error: {}".format(str(e)))
        print("\nUse --help for usage information.")
        sys.exit(1)