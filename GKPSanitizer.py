# Copyright (c) 2023 ot2i7ba
# https://github.com/ot2i7ba/
# This code is licensed under the MIT License (see LICENSE for details).

"""
GrayKey Password Sanitizer [GKPS]

- Improved error handling for file operations
- Check if the default file (DEFAULT_SOURCE_FILE) actually exists before falling back
- Specific exceptions caught (FileNotFoundError, PermissionError, etc.)
- Separation of UI/interaction and processing logic
- Using constants for commonly used default values
- Configurable upper limit for output file numbering (max_number)
- Example of how to extend the spinner function for async/stream-based writing
"""

import os
import re
import time
from itertools import cycle
import threading

DEFAULT_SOURCE_FILE       = "passwords.txt"
DEFAULT_ITEM_VALUE_PREFIX = "Item value:"
DEFAULT_ACCOUNT_PREFIX    = "Account:"
DEFAULT_FILE_PREFIX_PW    = "passwords_clean"
DEFAULT_FILE_PREFIX_COMBO = "combolist"
DEFAULT_MIN_LENGTH        = 4
DEFAULT_MAX_LENGTH        = 64
DEFAULT_MAX_NUMBER        = 99  # Number of possible "_00", "_01", ... output files

def clear_screen():
    """
    Clears the console screen.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def print_blank_line():
    """
    Prints a blank line for readability.
    """
    print()

def print_header(title):
    """
    Prints a formatted header with the given title.
    """
    clear_screen()
    print_blank_line()
    print(f"{title.center(60)}")
    print("=" * 60)
    print_blank_line()

def display_countdown(seconds):
    """
    Displays a countdown timer for the specified number of seconds.
    """
    for i in range(seconds, 0, -1):
        print(f"Starting in {i} second(s)...", end="\r", flush=True)
        time.sleep(1)
    print_blank_line()

def spinner_task(event):
    """
    Displays a simple spinner while the script is processing.
    The spinner stops when the event is set.
    (Potentially extend this for async/stream-based processing.)
    """
    spinner = cycle(['|', '/', '-', '\\'])
    while not event.is_set():
        print_blank_line()
        print(f"\rProcessing... {next(spinner)}", end="", flush=True)
        time.sleep(0.1)

def list_txt_files():
    """
    Lists all .txt files in the current directory.
    """
    return [f for f in os.listdir('.') if f.endswith('.txt')]

def find_available_filename(base_name, max_number=DEFAULT_MAX_NUMBER):
    """
    Finds an available filename with a numbered extension in the form:
    base_name_00.txt, base_name_01.txt, ..., base_name_XX.txt

    Returns:
        The first available filename as a string, or None if none are available.
    """
    for number in range(max_number + 1):
        new_name = f"{base_name}_{number:02d}.txt"
        if not os.path.exists(new_name):
            return new_name
    return None

def validate_input(prompt, default, min_value=None, max_value=None):
    """
    Validates user input for integer values with optional min and max limits.
    If the user presses ENTER, the 'default' value is used instead.
    """
    while True:
        try:
            user_input = input(prompt) or str(default)
            value = int(user_input)
            if (min_value is not None and value < min_value) or (max_value is not None and value > max_value):
                raise ValueError
            return value
        except ValueError:
            print("Invalid input. Please try again.")

def is_valid_email(email: str) -> bool:
    """
    Checks if the provided string looks like a valid email address.
    A simple regex is used here for demonstration purposes.
    """
    pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    return bool(pattern.match(email))

def process_file_passwordlist(
    source_file_path: str,
    output_file_path: str,
    prefix: str,
    min_length: int,
    max_length: int
) -> tuple[int, int]:
    """
    Processes the source file to extract unique passwords based on filters:
      - The password must contain the specified prefix (e.g., 'Item value:').
      - The password must be within the given length constraints.
      - The password should not start with '{' or '[' (to avoid JSON-like data).
      - No duplicates are allowed in the final output.

    Returns:
        (unique_count, duplicate_count)
    """
    seen_passwords = set()
    unique_count = 0
    duplicate_count = 0

    # Differentiated error handling for reading
    try:
        with open(source_file_path, 'r') as source_file:
            lines = source_file.readlines()
    except FileNotFoundError:
        print(f"Source file '{source_file_path}' was not found.")
        return 0, 0
    except PermissionError:
        print(f"No permission to read from '{source_file_path}'.")
        return 0, 0
    except OSError as e:
        print(f"OS error while reading '{source_file_path}': {e}")
        return 0, 0

    # Differentiated error handling for writing
    try:
        with open(output_file_path, 'w') as output_file:
            for line in lines:
                if prefix in line:
                    password = line.split(prefix, 1)[-1].strip()
                    if (min_length <= len(password) <= max_length
                            and not password.startswith('{"')
                            and not password.startswith('[')):
                        if password not in seen_passwords:
                            output_file.write(password + "\n")
                            seen_passwords.add(password)
                            unique_count += 1
                        else:
                            duplicate_count += 1
    except PermissionError:
        print(f"No permission to write to '{output_file_path}'.")
        return 0, 0
    except OSError as e:
        print(f"OS error while writing '{output_file_path}': {e}")
        return 0, 0

    return unique_count, duplicate_count


def process_file_combolist(
    source_file_path: str,
    output_file_path: str,
    account_prefix: str,
    password_prefix: str,
    min_length: int,
    max_length: int
) -> tuple[int, int]:
    """
    Processes the source file to create a combo list (email:password):
      - account_prefix, e.g., 'Account:', to extract an email from the remainder
      - password_prefix, e.g., 'Item value:', to extract the password from the remainder
      - Duplicates are filtered out, and JSON-like lines are excluded

    Returns:
        (unique_count, duplicate_count)
    """
    seen_combos = set()
    unique_count = 0
    duplicate_count = 0
    current_email = None

    # Differentiated error handling for reading
    try:
        with open(source_file_path, 'r') as source_file:
            lines = source_file.readlines()
    except FileNotFoundError:
        print(f"Source file '{source_file_path}' was not found.")
        return 0, 0
    except PermissionError:
        print(f"No permission to read from '{source_file_path}'.")
        return 0, 0
    except OSError as e:
        print(f"OS error while reading '{source_file_path}': {e}")
        return 0, 0

    # Differentiated error handling for writing
    try:
        with open(output_file_path, 'w') as output_file:
            for line in lines:
                if account_prefix in line:
                    email_candidate = line.split(account_prefix, 1)[-1].strip()
                    if is_valid_email(email_candidate):
                        current_email = email_candidate
                    else:
                        current_email = None
                elif password_prefix in line:
                    password_candidate = line.split(password_prefix, 1)[-1].strip()
                    if (current_email is not None
                            and min_length <= len(password_candidate) <= max_length
                            and not password_candidate.startswith('{"')
                            and not password_candidate.startswith('[')):
                        combo_line = f"{current_email}:{password_candidate}"
                        if combo_line not in seen_combos:
                            output_file.write(combo_line + "\n")
                            seen_combos.add(combo_line)
                            unique_count += 1
                        else:
                            duplicate_count += 1
    except PermissionError:
        print(f"No permission to write to '{output_file_path}'.")
        return 0, 0
    except OSError as e:
        print(f"OS error while writing '{output_file_path}': {e}")
        return 0, 0

    return unique_count, duplicate_count

def create_password_list_flow(
    source_file_path: str,
    prefix: str = DEFAULT_ITEM_VALUE_PREFIX,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = DEFAULT_MAX_LENGTH
) -> None:
    """
    Orchestrates the creation of a pure password list.
    Starts a spinner, calls the processing function, and displays the results.
    """
    output_filename = find_available_filename(DEFAULT_FILE_PREFIX_PW, max_number=DEFAULT_MAX_NUMBER)
    if not output_filename:
        print("Too many output files already exist. Please clean up the directory.")
        return

    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner_task, args=(stop_event,))
    spinner_thread.start()

    start_time = time.time()
    unique_count, duplicate_count = process_file_passwordlist(
        source_file_path,
        output_filename,
        prefix,
        min_length,
        max_length
    )
    stop_event.set()
    spinner_thread.join()
    end_time = time.time()

    if unique_count > 0 or duplicate_count > 0:
        print(f"\nResults have been saved to '{output_filename}'.")
        print(f"Number of unique passwords saved: {unique_count}")
        print(f"Number of duplicates encountered: {duplicate_count}")
        print(f"Processing time: {end_time - start_time:.2f} seconds.")
    else:
        print("\nNo passwords were processed, or the file was not found.")

def create_combolist_flow(
    source_file_path: str,
    account_prefix: str = DEFAULT_ACCOUNT_PREFIX,
    password_prefix: str = DEFAULT_ITEM_VALUE_PREFIX,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = DEFAULT_MAX_LENGTH
) -> None:
    """
    Orchestrates the creation of a combo list (email:password).
    Starts a spinner, calls the processing function, and displays the results.
    """
    output_filename = find_available_filename(DEFAULT_FILE_PREFIX_COMBO, max_number=DEFAULT_MAX_NUMBER)
    if not output_filename:
        print("Too many combolist files already exist. Please clean up the directory.")
        return

    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner_task, args=(stop_event,))
    spinner_thread.start()

    start_time = time.time()
    unique_count, duplicate_count = process_file_combolist(
        source_file_path,
        output_filename,
        account_prefix,
        password_prefix,
        min_length,
        max_length
    )
    stop_event.set()
    spinner_thread.join()
    end_time = time.time()

    if unique_count > 0 or duplicate_count > 0:
        print(f"\nA combolist has been saved to '{output_filename}'.")
        print(f"Number of unique email:password pairs saved: {unique_count}")
        print(f"Number of duplicates encountered: {duplicate_count}")
        print(f"Processing time: {end_time - start_time:.2f} seconds.")
    else:
        print("\nNo valid email:password pairs were processed, or the file was not found.")

def select_file():
    """
    Prompts the user to select a file or use the default (DEFAULT_SOURCE_FILE).
    Returns the chosen filename or None if the user exits.
    """
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
    print("[e] Exit GrayKey Password Sanitizer")
    print_blank_line()

    while True:
        choice = input("Select a file by number, press ENTER for default, or 'e' to exit: ").strip().lower()

        if choice == 'e':
            return None

        if not choice:
            # Check whether the default file exists
            if os.path.exists(DEFAULT_SOURCE_FILE):
                return DEFAULT_SOURCE_FILE
            else:
                print(f"Default file '{DEFAULT_SOURCE_FILE}' was not found. Please select a file manually.")
                continue

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(txt_files):
                return txt_files[idx]
            else:
                print("Invalid selection. Try again or press ENTER for default.")
        except ValueError:
            print("Invalid input. Try again or press ENTER for default.")

def main():
    """
    Main function to control the flow of the GrayKey Password Sanitizer.
    """
    while True:
        try:
            print_header("GrayKey Password Sanitizer [GKPS] v0.0.1 by ot2i7ba")

            source_file_path = select_file()
            if not source_file_path:
                print("No valid file selected. Exiting the program.")
                return

            print_blank_line()
            print("Please choose one of the following options:")
            print_blank_line()
            print("[1] Create a Password List (only passwords)")
            print("[2] Create a Combo List (email:password)")
            print_blank_line()

            user_choice = input("Your choice [1/2]: ").strip()

            if user_choice == '2':
                # Combo list flow
                print_blank_line()
                print("You chose to create a combo list (email:password)")
                print_blank_line()
                account_prefix = input(f"Enter the prefix for accounts (default: '{DEFAULT_ACCOUNT_PREFIX}'): ") or DEFAULT_ACCOUNT_PREFIX
                password_prefix = input(f"Enter the prefix for passwords (default: '{DEFAULT_ITEM_VALUE_PREFIX}'): ") or DEFAULT_ITEM_VALUE_PREFIX
                min_length = validate_input(f"Enter the minimum password length (default: {DEFAULT_MIN_LENGTH}): ", DEFAULT_MIN_LENGTH, min_value=1)
                max_length = validate_input(f"Enter the maximum password length (default: {DEFAULT_MAX_LENGTH}): ", DEFAULT_MAX_LENGTH, min_value=min_length)

                create_combolist_flow(
                    source_file_path,
                    account_prefix=account_prefix,
                    password_prefix=password_prefix,
                    min_length=min_length,
                    max_length=max_length
                )

            else:
                # Password list flow
                print_blank_line()
                print("You chose to create a password list (only passwords)")
                print_blank_line()
                prefix = input(f"Enter the prefix for line filtering (default: '{DEFAULT_ITEM_VALUE_PREFIX}'): ") or DEFAULT_ITEM_VALUE_PREFIX
                min_length = validate_input(f"Enter the minimum password length (default: {DEFAULT_MIN_LENGTH}): ", DEFAULT_MIN_LENGTH, min_value=1)
                max_length = validate_input(f"Enter the maximum password length (default: {DEFAULT_MAX_LENGTH}): ", DEFAULT_MAX_LENGTH, min_value=min_length)

                create_password_list_flow(
                    source_file_path,
                    prefix=prefix,
                    min_length=min_length,
                    max_length=max_length
                )

            print_blank_line()
            display_countdown(3)
            clear_screen()

        except KeyboardInterrupt:
            print("\nOperation canceled by user. Exiting gracefully...")
            return
        # Example of more specific errors:
        except (FileNotFoundError, PermissionError) as e:
            print(f"\nFile/Permission error: {e}")
            return
        except OSError as e:
            print(f"\nOS error: {e}")
            return
        except Exception as e:
            # Fallback if something unexpected happens
            print(f"\nAn unexpected error occurred: {type(e).__name__} - {e}")
            return

if __name__ == "__main__":
    main()
