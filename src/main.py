#!/usr/bin/env python3
"""
IDA Native Python API - Binary Export to BinaryX-Graph JSON Format

This script uses native IDA Python SDK in headless mode to export binary analysis data
to a JSON format compatible with BinaryX-Graph for Neo4j graph database import.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import utils
import extractors

import idapro
import idaapi
import ida_auto


def analyze_binary(file_path: str, min_string_length: int = 4) -> dict:

    print(f'Processing file: {file_path}')

    print('Extracting binary information...')
    binary_info = extractors.extract_binary_info(file_path)

    print('Extracting functions...')
    functions, address_to_name = extractors.extract_functions()

    print('Extracting imports...')
    imports = extractors.extract_imports()

    print('Extracting exports...')
    exports = extractors.extract_exports()

    print('Extracting strings...')
    strings = extractors.extract_strings(min_string_length)

    print('Extracting call relationships...')
    calls = extractors.extract_calls(address_to_name, imports)

    return {
        'binary_info': binary_info,
        'functions': functions,
        'imports': imports,
        'exports': exports,
        'strings': strings,
        'calls': calls
    }


def export_to_json(data: dict, output_path: str) -> None:

    output_dir = Path(output_path).parent
    if output_dir and not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)

    print(f'Writing output to: {output_path}')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f'Output saved to: {output_path}')


def print_summary(data: dict) -> None:

    binary_info = data['binary_info']

    print('\n=== Export Summary ===')
    print(f'Binary: {binary_info["name"]}')
    print(f'File Type: {binary_info["file_type"]["type"]} ({binary_info["file_type"]["architecture"]})')
    print(f'Functions: {len(data["functions"])}')
    print(f'Imports: {len(data["imports"])}')
    print(f'Exports: {len(data["exports"])}')
    print(f'Strings: {len(data["strings"])}')
    print(f'Calls: {len(data["calls"])}')

def run_analysis_headless(input_file: str, output_path: str, min_string_length: int = 4) -> dict:

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    print(f'Opening database: {input_file}')
    idapro.open_database(input_file, True)

    print('Waiting for auto-analysis to complete...')
    ida_auto.auto_wait()

    file_path = idaapi.get_input_file_path()

    data = analyze_binary(file_path, min_string_length)

    export_to_json(data, output_path)

    print_summary(data)

    idapro.close_database()

    return data


def main():
    parser = argparse.ArgumentParser(
        description='Export binary analysis data to BinaryX-Graph JSON format using IDA Pro in headless mode',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Usage Examples:
    # Analyze binary file with IDA in headless mode:
    python src/main.py -f binary.exe -o output.json

    # With custom string length:
    python src/main.py -f sample.dll -o output.json --min-string-length 6

Output Format:
    The output JSON file contains:
    - binary_info: File metadata and hashes
    - functions: List of functions with addresses and complexity
    - strings: Extracted strings with addresses
    - imports: Imported functions with library names
    - exports: Exported functions with addresses
    - calls: Function call relationships
'''
    )

    parser.add_argument(
        '-f', '--input-file',
        help='Binary input file to analyze',
        type=str,
        required=True
    )

    parser.add_argument(
        '-o', '--output',
        help='Output JSON file path',
        type=str,
        required=True
    )

    parser.add_argument(
        '--min-string-length',
        help='Minimum string length to include (default: 4)',
        type=int,
        default=4
    )

    args = parser.parse_args()

    try:
        run_analysis_headless(args.input_file, args.output, args.min_string_length)
        return 0

    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())