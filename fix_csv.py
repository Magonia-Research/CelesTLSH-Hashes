#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A CLI script to update, fix, and verify threat intelligence CSV files.

This script provides two main normalization modes:
1.  --normalize-malware: (Default) Fixes malware CSVs that are in an old
    8-column format or have a mismatched 11-column header with 8-column data.
2.  --normalize-attack-tools: Fixes attack tool CSVs that have 10 columns
    and contain unescaped commas in the 'File Type' field.

The '--test' mode performs a deep verification using the 'tlsh' library.
"""

import os
import csv
import argparse
from typing import List, Tuple

# Attempt to import the required 'tlsh' library for testing
try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

# --- Configuration ---
HEADER_11_COL: Tuple[str, ...] = (
    'Repo Name', 'File Name', 'File Type', 'Release Version', 'TLSH Hash',
    'Commit_Distance', 'Lines Changed', 'SHA256 Hash', 'Imphash',
    'Date Added', 'Intel'
)
# Default TLSH hashes for testing each mode
MALWARE_TEST_HASH: str = (
    "T1FE360823FC9710D6C67EE134C6A66732BF71745983317B836EA049666E1AFE46A3D300"
)
ATTACK_TOOL_TEST_HASH: str = (
    "T199A6337BB48D242BFA2A9736946084737E7E16E8D78B301229F5493A437D1B2F03745"
)
DEFAULT_MAX_DISTANCE: int = 50


def find_csv_files(root_dir: str) -> List[str]:
    """Finds all CSV files recursively in a directory."""
    csv_files: List[str] = []
    print(f"Searching for CSV files in '{root_dir}'...")
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.lower().endswith('.csv'):
                csv_files.append(os.path.join(root, file))
    return csv_files


def normalize_malware_csv(file_path: str) -> Tuple[bool, str, str]:
    """
    Updates or fixes a malware CSV file to the standard 11-column format.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
            reader = csv.reader(infile)
            try:
                header: List[str] = [h.strip() for h in next(reader)]
                data_rows: List[List[str]] = list(reader)
            except StopIteration:
                return False, "SKIPPED", f"File '{file_path}' is empty."

        header_len = len(header)
        first_row_len = len(data_rows[0]) if data_rows else 0

        if header_len == 11 and first_row_len == 11:
            return False, "SKIPPED", "File is already in the correct format."

        if header_len == 8 or (header_len == 11 and first_row_len == 8):
            action = "Fixed" if header_len == 11 else "Updated"
            updated_rows: List[List[str]] = [list(HEADER_11_COL)]
            for i, row in enumerate(data_rows, start=2):
                if len(row) != 8:
                    print(f"      [!] Warning: Skipping malformed malware row {i}")
                    continue
                new_row: List[str] = [
                    row[0], row[1], 'N/A', row[2], row[3], 'N/A', 'N/A',
                    row[4], row[5], row[6], row[7]
                ]
                updated_rows.append(new_row)

            with open(file_path, 'w', newline='', encoding='utf-8') as outfile:
                writer = csv.writer(outfile)
                writer.writerows(updated_rows)

            return True, "SUCCESS", f"File was successfully {action}."
        else:
            msg = (f"File has an unrecognized malware format "
                   f"(Header: {header_len}, Row: {first_row_len}).")
            return False, "SKIPPED", msg

    except Exception as e:
        return False, "ERROR", f"An unexpected error occurred: {e}"


def normalize_attack_tool_csv(file_path: str) -> Tuple[bool, str, str]:
    """
    Fixes an attack tool CSV file to the standard 11-column format.
    This handles 10-column files with commas in the 'File Type' field.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
            reader = csv.reader(infile)
            try:
                header: List[str] = [h.strip() for h in next(reader)]
                data_rows: List[List[str]] = list(reader)
            except StopIteration:
                return False, "SKIPPED", f"File '{file_path}' is empty."

        if len(header) != 10:
            return False, "SKIPPED", f"File is not a 10-column attack tool CSV."

        updated_rows: List[List[str]] = [list(HEADER_11_COL)]
        for i, row in enumerate(data_rows, start=2):
            if len(row) != 10:
                print(f"      [!] Warning: Skipping malformed attack tool row {i}")
                continue
            
            # Fix commas in the 'File Type' field (index 2)
            file_type = row[2].replace(',', ';')
            
            # Reconstruct row to the 11-column format
            new_row: List[str] = [
                row[0], row[1], file_type, row[3], row[4], row[5], 
                'N/A',  # Insert 'Lines Changed'
                row[6], row[7], row[8], row[9]
            ]
            updated_rows.append(new_row)

        with open(file_path, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.writer(outfile)
            writer.writerows(updated_rows)

        return True, "SUCCESS", "File was successfully fixed."

    except Exception as e:
        return False, "ERROR", f"An unexpected error occurred: {e}"


def verify_and_match_hashes(
    file_path: str,
    reference_tlsh: str,
    max_distance: int
) -> Tuple[bool, bool]:
    """Tests a CSV by calculating TLSH distances against a reference hash."""
    print(f"    -> Deep Test: '{os.path.basename(file_path)}'")
    matches_found: bool = False
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
            reader = csv.DictReader(infile)
            if 'TLSH Hash' not in reader.fieldnames:
                print("       [FAILURE] 'TLSH Hash' column not found.")
                return False, False

            for i, row in enumerate(reader, start=2):
                current_tlsh = row.get('TLSH Hash', '').strip()
                if not current_tlsh.startswith('T1'):
                    continue
                try:
                    distance = tlsh.diff(reference_tlsh, current_tlsh)
                    if distance < max_distance:
                        matches_found = True
                        sha256 = row.get('SHA256 Hash', 'N/A')
                        print(f"       [MATCH FOUND] File: {os.path.basename(file_path)}, "
                              f"Row: {i}, Distance: {distance}, SHA256: {sha256}")
                except ValueError:
                    continue
        
        if not matches_found:
            print(f"       [INFO] No matches found below distance {max_distance}.")
        return True, matches_found

    except Exception as e:
        print(f"       [ERROR] Test failed: Could not read or parse file: {e}")
        return False, False


def main() -> None:
    """Main function to parse CLI arguments and orchestrate the flow."""
    parser = argparse.ArgumentParser(
        description="Update, fix, and verify threat intelligence CSV files.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--normalize-malware', action='store_true', default=True,
        help="Normalize malware CSVs (default behavior)."
    )
    mode_group.add_argument(
        '--normalize-attack-tools', action='store_true',
        help="Normalize attack tool CSVs (10-column format with comma issues)."
    )
    # General arguments
    parser.add_argument(
        '-f', '--file', type=str, help="Path to a single CSV file to process."
    )
    parser.add_argument(
        '-d', '--directory', type=str, default=os.getcwd(),
        help="Directory to scan for CSVs (default: current directory)."
    )
    parser.add_argument(
        '--test', action='store_true',
        help="Run a deep verification test on all processed files."
    )
    parser.add_argument(
        '--max-distance', type=int, default=DEFAULT_MAX_DISTANCE,
        help=f"Maximum distance for a TLSH match (Default: {DEFAULT_MAX_DISTANCE})."
    )
    args = parser.parse_args()

    if args.test and not TLSH_AVAILABLE:
        print("\n[ERROR] The '--test' feature requires the 'tlsh' library.")
        print("Please install it by running: pip install tlsh")
        return

    # Determine which function and test hash to use
    if args.normalize_attack_tools:
        normalize_func = normalize_attack_tool_csv
        reference_tlsh = ATTACK_TOOL_TEST_HASH
        print("\n--- Running in Attack Tool Normalization Mode ---")
    else:
        normalize_func = normalize_malware_csv
        reference_tlsh = MALWARE_TEST_HASH
        print("\n--- Running in Malware Normalization Mode (Default) ---")

    # Determine files to process
    files_to_process = []
    if args.file:
        if os.path.exists(args.file):
            files_to_process = [args.file]
    else:
        files_to_process = find_csv_files(args.directory)

    if not files_to_process:
        print("No CSV files found to process.")
        return

    print(f"\nFound {len(files_to_process)} CSV files. Starting process...\n")
    changed_count, skipped_count = 0, 0
    tests_passed, tests_failed = 0, 0
    files_with_matches = []

    for file_path in files_to_process:
        print(f"  -> Processing: {file_path}")
        was_changed, status, message = normalize_func(file_path)
        print(f"     [{status}] {message}")

        if was_changed:
            changed_count += 1
        elif status == "SKIPPED":
            skipped_count += 1

        if args.test:
            is_readable, found_match = verify_and_match_hashes(
                file_path, reference_tlsh, args.max_distance
            )
            if is_readable:
                tests_passed += 1
            else:
                tests_failed += 1
            if found_match:
                files_with_matches.append(file_path)
    
    # --- Final Summary Report ---
    print("\n" + "="*60)
    print(" " * 22 + "Process Summary")
    print("="*60)
    print(f"Total CSV Files Scanned: {len(files_to_process)}")
    print(f"Files Fixed or Updated: {changed_count}")
    print(f"Files Skipped: {skipped_count}")
    if args.test:
        print("-" * 60)
        print(" " * 18 + "Verification Test Summary")
        print("-" * 60)
        print(f"Total Tests Run: {len(files_to_process)}")
        print(f"Tests Passed (Readable): {tests_passed}")
        print(f"Tests Failed (Unreadable): {tests_failed}")
        if files_with_matches:
            print("-" * 60)
            print(f"--- Files with TLSH Matches (Distance < {args.max_distance}) ---")
            for file_path in files_with_matches:
                print(f"  - {file_path}")
        else:
            print("\nNo files contained TLSH matches below the threshold.")
    print("="*60)


if __name__ == "__main__":
    main()
