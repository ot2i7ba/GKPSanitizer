#!/usr/bin/env python3
"""
GrayKey Password Sanitizer [GKPS]
Integrated script with asynchronous processing, refined RegEx extraction patterns,
improved length checking, configurable output file names (excluded from file selection),
and optional generation of birthdate-based passwords.

Features:
- Asynchronous line-by-line processing of large files using aiofiles.
- Extraction of passwords or email:password combinations using precise RegEx patterns.
- Improved length checking: Only values that are within the specified minimum and maximum lengths
  and that do not appear as JSON/array strings are considered.
- Output file name prefixes for generated files are defined via constants and are excluded from the file selection menu.
- When generating a password list, the user is asked whether to include birthdate-based passwords.
  If yes, the user must provide a birth date in DD.MM.YYYY format (with two-digit day/month and four-digit year).
  From this date, all possible password combinations are generated and appended at the end of the output file,
  ensuring that duplicates (already extracted from the GrayKey file) are not added.
  
Requirements:
- aiofiles (install with: pip install aiofiles)
- Optional: email_validator (install with: pip install email_validator)
"""

import os
import re
import time
import asyncio
from itertools import cycle

# External libraries for asynchronous file processing and email validation
try:
    import aiofiles
except ImportError:
    print("The aiofiles module must be installed (pip install aiofiles).")
    raise

try:
    from email_validator import validate_email as ev_validate_email, EmailNotValidError
except ImportError:
    ev_validate_email = None

# --- Constants ---
DEFAULT_SOURCE_FILE       = "graykey.txt"
DEFAULT_ITEM_VALUE_PREFIX = "Item value:"
DEFAULT_ACCOUNT_PREFIX    = "Account:"
DEFAULT_FILE_PREFIX_PW    = "passwords"      # Output file prefix for password list
DEFAULT_FILE_PREFIX_COMBO = "combolist"      # Output file prefix for combo list
DEFAULT_MIN_LENGTH        = 4
DEFAULT_MAX_LENGTH        = 20             # Changed default maximum length from 64 to 20
DEFAULT_MAX_NUMBER        = 99             # Allowed file numbers: _00 to _99

# --- Security Functions ---
def secure_filename(filename: str) -> str:
    """Removes any potentially problematic characters from the filename."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", filename)

def is_secure_path(path: str) -> bool:
    """Checks if the given path is relative and does not contain any path traversal attempts."""
    if os.path.isabs(path):
        return False
    if ".." in path or "/" in path or "\\" in path:
        return False
    return True

def find_available_filename(base_name: str, max_number: int = DEFAULT_MAX_NUMBER) -> str:
    """
    Searches for an available filename in the format base_name_XX.txt.
    The base name is first sanitized using secure_filename.
    """
    base_name = secure_filename(base_name)
    for number in range(max_number + 1):
        new_name = f"{base_name}_{number:02d}.txt"
        if is_secure_path(new_name) and not os.path.exists(new_name):
            return new_name
    return None

def is_valid_email(email: str) -> bool:
    """
    Checks whether the given email address appears valid using the email_validator library (if available)
    or an extended RegEx pattern.
    """
    if ev_validate_email:
        try:
            ev_validate_email(email)
            return True
        except EmailNotValidError:
            return False
    else:
        pattern = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
        return bool(pattern.match(email))

# --- Birthdate Combination Generation ---
def birthdate_combos(birthdate: str) -> set:
    """
    Given a birth date string in the format DD.MM.YYYY, generate a set of possible
    password combinations based on the day, month, and year.

    The function considers the following:
      - Day: with leading zero and without (e.g. "01" and "1")
      - Month: with leading zero and without (e.g. "02" and "2")
      - Year: full year (e.g. "1978") and the last two digits (e.g. "78")
    
    Then it generates all ordered concatenations of any non-empty subset of these segments.
    Additionally, for any combination that uses the two-digit year ("78"), a variant is added
    with the first two digits of the full year ("19") prepended.
    
    Returns a set of generated password strings.
    """
    pattern = re.compile(r'^(\d{2})\.(\d{2})\.(\d{4})$')
    m = pattern.match(birthdate)
    if not m:
        print("Invalid birth date format. Please use DD.MM.YYYY with two-digit day/month and four-digit year.")
        return set()
    d_lead, m_lead, y_full = m.group(1), m.group(2), m.group(3)
    d_nolead = str(int(d_lead))
    m_nolead = str(int(m_lead))
    y_first = y_full[:2]
    y_last = y_full[2:]
    
    results = set()
    day_opts = [d_lead, d_nolead]
    month_opts = [m_lead, m_nolead]
    year_opts = [y_full, y_last]
    
    # Single segments
    for d in day_opts:
        results.add(d)
    for m_val in month_opts:
        results.add(m_val)
    for y in year_opts:
        results.add(y)
    
    # Two-segment combinations (preserving order: day then month, day then year, month then year)
    for d in day_opts:
        for m_val in month_opts:
            results.add(d + m_val)
    for d in day_opts:
        for y in year_opts:
            combo = d + y
            results.add(combo)
            if y == y_last:
                results.add(y_first + combo)
    for m_val in month_opts:
        for y in year_opts:
            combo = m_val + y
            results.add(combo)
            if y == y_last:
                results.add(y_first + combo)
    
    # Three-segment combinations: day, month, year
    for d in day_opts:
        for m_val in month_opts:
            for y in year_opts:
                combo = d + m_val + y
                results.add(combo)
                if y == y_last:
                    results.add(y_first + combo)
    
    # Filter out combinations shorter than the minimum length (default is 4)
    filtered = {x for x in results if len(x) >= DEFAULT_MIN_LENGTH}
    return filtered

# --- Asynchronous Processing Functions with Refined RegEx Extraction and Improved Length Checking ---
async def process_file_passwordlist(source_file_path: str,
                                    output_file_path: str,
                                    prefix: str,
                                    min_length: int,
                                    max_length: int) -> tuple[int, int]:
    """
    Asynchronously processes a password list.
    Reads the file line by line and extracts values that begin with the specified prefix using a RegEx pattern.
    After extraction, it checks whether the value's length is between min_length and max_length
    and excludes JSON/array-like content.
    """
    seen_passwords = set()
    unique_count = 0
    duplicate_count = 0
    pattern_value = re.compile(r"^\s*" + re.escape(prefix) + r"\s*(.+?)\s*$")
    
    try:
        async with aiofiles.open(source_file_path, mode='r') as source_file, \
                   aiofiles.open(output_file_path, mode='w') as output_file:
            async for line in source_file:
                match = pattern_value.match(line)
                if match:
                    password = match.group(1).strip()
                    # Length check: Only consider values within the specified range
                    if len(password) < min_length or len(password) > max_length:
                        continue
                    # Exclude JSON/array-like content
                    if (password.startswith('{') and password.endswith('}')) or \
                       (password.startswith('[') and password.endswith(']')):
                        continue
                    if password not in seen_passwords:
                        await output_file.write(password + "\n")
                        seen_passwords.add(password)
                        unique_count += 1
                    else:
                        duplicate_count += 1
    except Exception as e:
        print(f"Error processing file: {e}")
        return 0, 0

    return unique_count, duplicate_count

async def process_file_combolist(source_file_path: str,
                                 output_file_path: str,
                                 account_prefix: str,
                                 password_prefix: str,
                                 min_length: int,
                                 max_length: int) -> tuple[int, int]:
    """
    Asynchronously processes a combo list (email:password).
    Uses RegEx patterns to precisely extract both account and password lines.
    Only if a valid email is extracted are subsequent password lines combined with it,
    provided the password meets the length requirements and is not JSON/array-like.
    """
    seen_combos = set()
    unique_count = 0
    duplicate_count = 0
    current_email = None

    pattern_account = re.compile(r"^\s*" + re.escape(account_prefix) + r"\s*(.+?)\s*$")
    pattern_password = re.compile(r"^\s*" + re.escape(password_prefix) + r"\s*(.+?)\s*$")

    try:
        async with aiofiles.open(source_file_path, mode='r') as source_file, \
                   aiofiles.open(output_file_path, mode='w') as output_file:
            async for line in source_file:
                match_account = pattern_account.match(line)
                if match_account:
                    email_candidate = match_account.group(1).strip()
                    if is_valid_email(email_candidate):
                        current_email = email_candidate
                    else:
                        current_email = None
                    continue  # Proceed to the next line
                match_password = pattern_password.match(line)
                if match_password:
                    password_candidate = match_password.group(1).strip()
                    if current_email is not None and (min_length <= len(password_candidate) <= max_length):
                        if (password_candidate.startswith('{') and password_candidate.endswith('}')) or \
                           (password_candidate.startswith('[') and password_candidate.endswith(']')):
                            continue
                        combo_line = f"{current_email}:{password_candidate}"
                        if combo_line not in seen_combos:
                            await output_file.write(combo_line + "\n")
                            seen_combos.add(combo_line)
                            unique_count += 1
                        else:
                            duplicate_count += 1
    except Exception as e:
        print(f"Error processing file: {e}")
        return 0, 0

    return unique_count, duplicate_count

# --- Asynchronous Spinner (UI) ---
async def spinner_task(stop_event: asyncio.Event):
    """Asynchronous spinner to display progress without blocking the event loop."""
    spinner = cycle(['|', '/', '-', '\\'])
    while not stop_event.is_set():
        print(f"\rProcessing... {next(spinner)}", end="", flush=True)
        await asyncio.sleep(0.1)
    print("\r", end="")  # Clear the spinner line

# --- UI Functions ---
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_blank_line():
    print()

def print_header(title: str):
    clear_screen()
    print_blank_line()
    print(f"{title.center(60)}")
    print("=" * 60)
    print_blank_line()

def display_countdown(seconds: int):
    for i in range(seconds, 0, -1):
        print(f"Starting in {i} second(s)...", end="\r", flush=True)
        time.sleep(1)
    print_blank_line()

def list_txt_files() -> list:
    """
    Returns a list of .txt files in the current directory, excluding files that
    start with the defined generated output file prefixes.
    """
    all_txt_files = [f for f in os.listdir('.') if f.endswith('.txt')]
    excluded_prefixes = (DEFAULT_FILE_PREFIX_PW, DEFAULT_FILE_PREFIX_COMBO)
    return [f for f in all_txt_files if not f.startswith(excluded_prefixes)]

def validate_input(prompt: str, default: int, min_value: int = None, max_value: int = None) -> int:
    while True:
        try:
            user_input = input(prompt) or str(default)
            value = int(user_input)
            if (min_value is not None and value < min_value) or (max_value is not None and value > max_value):
                raise ValueError
            return value
        except ValueError:
            print("Invalid input. Please try again.")

def select_file() -> str:
    txt_files = list_txt_files()
    if not txt_files:
        print("No .txt files found in the current directory.")
        return None

    print("Available .txt files:")
    print_blank_line()
    for idx, file in enumerate(txt_files, start=1):
        print(f"[{idx}] {file}")
    print_blank_line()
    print("[ENTER] Use default:", DEFAULT_SOURCE_FILE)
    print("[e] Exit")
    print_blank_line()

    while True:
        choice = input("Choose a file (number, ENTER for default or 'e' to exit): ").strip().lower()
        if choice == 'e':
            return None
        if not choice:
            if is_secure_path(DEFAULT_SOURCE_FILE) and os.path.exists(DEFAULT_SOURCE_FILE):
                return DEFAULT_SOURCE_FILE
            else:
                print(f"Default file '{DEFAULT_SOURCE_FILE}' was not found or is not secure. Please choose manually.")
                continue
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(txt_files):
                return txt_files[idx]
            else:
                print("Invalid selection. Please try again or press ENTER for default.")
        except ValueError:
            print("Invalid input. Please try again or press ENTER for default.")

# --- Main Flow ---
async def create_password_list_flow(source_file_path: str,
                                    prefix: str = DEFAULT_ITEM_VALUE_PREFIX,
                                    min_length: int = DEFAULT_MIN_LENGTH,
                                    max_length: int = DEFAULT_MAX_LENGTH) -> None:
    # Ask if birthdate-based passwords should be included
    include_birthdate = input("\nInclude birthdate-based passwords? (y/n): ").strip().lower()
    birthdate_passwords = set()
    if include_birthdate == "y":
        birthdate = input("Enter birth date (DD.MM.YYYY): ").strip()
        birthdate_passwords = birthdate_combos(birthdate)
        if not birthdate_passwords:
            print("No valid birthdate combinations generated. Continuing without them.")
    
    output_filename = find_available_filename(DEFAULT_FILE_PREFIX_PW, max_number=DEFAULT_MAX_NUMBER)
    if not output_filename:
        print("Too many output files already exist. Please clean up the directory.")
        return

    stop_event = asyncio.Event()
    spinner = asyncio.create_task(spinner_task(stop_event))

    start_time = time.time()
    unique_count, duplicate_count = await process_file_passwordlist(
        source_file_path, output_filename, prefix, min_length, max_length)
    stop_event.set()
    await spinner
    end_time = time.time()

    # Append birthdate-based passwords at the end, avoiding duplicates.
    if birthdate_passwords:
        try:
            async with aiofiles.open(output_filename, mode='r') as f:
                content = await f.read()
            existing_passwords = set(line.strip() for line in content.splitlines() if line.strip())
            async with aiofiles.open(output_filename, mode='a') as f:
                for pwd in sorted(birthdate_passwords):
                    if pwd not in existing_passwords:
                        await f.write(pwd + "\n")
                        unique_count += 1
                        existing_passwords.add(pwd)
        except Exception as e:
            print(f"Error appending birthdate passwords: {e}")

    if unique_count > 0 or duplicate_count > 0:
        print(f"\nResults have been saved in '{output_filename}'.")
        print(f"Number of unique passwords: {unique_count}")
        print(f"Number of duplicates: {duplicate_count}")
        print(f"Processing time: {end_time - start_time:.2f} seconds.")
    else:
        print("\nNo passwords were processed or the file was not found.")

async def create_combolist_flow(source_file_path: str,
                                account_prefix: str = DEFAULT_ACCOUNT_PREFIX,
                                password_prefix: str = DEFAULT_ITEM_VALUE_PREFIX,
                                min_length: int = DEFAULT_MIN_LENGTH,
                                max_length: int = DEFAULT_MAX_LENGTH) -> None:
    output_filename = find_available_filename(DEFAULT_FILE_PREFIX_COMBO, max_number=DEFAULT_MAX_NUMBER)
    if not output_filename:
        print("Too many combo files already exist. Please clean up the directory.")
        return

    stop_event = asyncio.Event()
    spinner = asyncio.create_task(spinner_task(stop_event))

    start_time = time.time()
    unique_count, duplicate_count = await process_file_combolist(
        source_file_path, output_filename, account_prefix, password_prefix, min_length, max_length)
    stop_event.set()
    await spinner
    end_time = time.time()

    if unique_count > 0 or duplicate_count > 0:
        print(f"\nCombo list has been saved in '{output_filename}'.")
        print(f"Number of unique email:password pairs: {unique_count}")
        print(f"Number of duplicates: {duplicate_count}")
        print(f"Processing time: {end_time - start_time:.2f} seconds.")
    else:
        print("\nNo valid email:password pairs were processed or the file was not found.")

async def main():
    while True:
        try:
            print_header("GrayKey Password Sanitizer [GKPS] v0.0.2")
            source_file_path = select_file()
            if not source_file_path:
                print("No valid file selected. Exiting the program.")
                return

            print_blank_line()
            print("Please choose one of the following options:")
            print_blank_line()
            print("[1] Create password list (passwords only)")
            print("[2] Create combo list (email:password)")
            print_blank_line()

            user_choice = input("Your choice [1/2]: ").strip()

            if user_choice == '2':
                print_blank_line()
                print("You have chosen to create a combo list.")
                print_blank_line()
                account_prefix = input(f"Prefix for accounts (default: '{DEFAULT_ACCOUNT_PREFIX}'): ") or DEFAULT_ACCOUNT_PREFIX
                password_prefix = input(f"Prefix for passwords (default: '{DEFAULT_ITEM_VALUE_PREFIX}'): ") or DEFAULT_ITEM_VALUE_PREFIX
                min_length = validate_input(f"Minimum password length (default: {DEFAULT_MIN_LENGTH}): ", DEFAULT_MIN_LENGTH, min_value=1)
                max_length = validate_input(f"Maximum password length (default: {DEFAULT_MAX_LENGTH}): ", DEFAULT_MAX_LENGTH, min_value=min_length)

                await create_combolist_flow(source_file_path, account_prefix=account_prefix,
                                            password_prefix=password_prefix, min_length=min_length, max_length=max_length)
            else:
                print_blank_line()
                print("You have chosen to create a password list.")
                print_blank_line()
                prefix = input(f"Prefix for filtering lines (default: '{DEFAULT_ITEM_VALUE_PREFIX}'): ") or DEFAULT_ITEM_VALUE_PREFIX
                min_length = validate_input(f"Minimum password length (default: {DEFAULT_MIN_LENGTH}): ", DEFAULT_MIN_LENGTH, min_value=1)
                max_length = validate_input(f"Maximum password length (default: {DEFAULT_MAX_LENGTH}): ", DEFAULT_MAX_LENGTH, min_value=min_length)

                await create_password_list_flow(source_file_path, prefix=prefix, min_length=min_length, max_length=max_length)

            print_blank_line()
            display_countdown(3)
            clear_screen()
        except KeyboardInterrupt:
            print("\nOperation cancelled by user. Exiting the program...")
            return
        except Exception as e:
            print(f"\nAn unexpected error occurred: {type(e).__name__} - {e}")
            return

if __name__ == "__main__":
    asyncio.run(main())