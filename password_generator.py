import random
import string
import argparse

def generate_password(length=12, use_uppercase=True, use_lowercase=True, use_numbers=True, use_symbols=False):
    """
    Generates a random password based on specified criteria.

    Args:
        length (int): The desired length of the password.
        use_uppercase (bool): Whether to include uppercase letters (A-Z).
        use_lowercase (bool): Whether to include lowercase letters (a-z).
        use_numbers (bool): Whether to include numbers (0-9).
        use_symbols (bool): Whether to include symbols (!@#$%^&* etc.).

    Returns:
        str: The generated password, or an error message if no character types are selected.
    """
    char_pool = ""
    password = [] # Use a list to build the password for easier shuffling

    # Add characters to the pool based on selected options
    if use_uppercase:
        char_pool += string.ascii_uppercase
        # Ensure at least one uppercase character is included if selected
        password.append(random.choice(string.ascii_uppercase))
    if use_lowercase:
        char_pool += string.ascii_lowercase
        # Ensure at least one lowercase character is included if selected
        password.append(random.choice(string.ascii_lowercase))
    if use_numbers:
        char_pool += string.digits
        # Ensure at least one digit is included if selected
        password.append(random.choice(string.digits))
    if use_symbols:
        char_pool += string.punctuation
        # Ensure at least one symbol is included if selected
        password.append(random.choice(string.punctuation))

    # Check if any character type was selected
    if not char_pool:
        return "Error: Please select at least one character type for password generation."

    # Fill the rest of the password length with random characters from the combined pool
    # Adjust length to account for characters already added to ensure variety
    remaining_length = length - len(password)
    for _ in range(remaining_length):
        password.append(random.choice(char_pool))

    # Shuffle the password list to randomize the position of the initially guaranteed characters
    random.shuffle(password)

    # Join the list into a string and return
    return "".join(password)

if __name__ == "__main__":
    # Set up argument parser for command-line interaction
    parser = argparse.ArgumentParser(
        description="Generate a strong, random password.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-l", "--length", type=int, default=12,
        help="Desired length of the password (default: 12, min: 6, max: 32)."
    )
    parser.add_argument(
        "-u", "--uppercase", action="store_true",
        help="Include uppercase letters (A-Z). Default: True."
    )
    parser.add_argument(
        "-L", "--lowercase", action="store_true",
        help="Include lowercase letters (a-z). Default: True."
    )
    parser.add_argument(
        "-n", "--numbers", action="store_true",
        help="Include numbers (0-9). Default: True."
    )
    parser.add_argument(
        "-s", "--symbols", action="store_true",
        help="Include symbols (!@#$%^&* etc.). Default: False."
    )

    args = parser.parse_args()

    # Apply default values if no specific flags are provided for character types
    # This ensures that by default, it includes uppercase, lowercase, and numbers
    if not (args.uppercase or args.lowercase or args.numbers or args.symbols):
        args.uppercase = True
        args.lowercase = True
        args.numbers = True

    # Validate password length
    if not (6 <= args.length <= 32):
        print("Error: Password length must be between 6 and 32 characters.")
    else:
        # Generate and print the password
        password = generate_password(
            length=args.length,
            use_uppercase=args.uppercase,
            use_lowercase=args.lowercase,
            use_numbers=args.numbers,
            use_symbols=args.symbols
        )
        print(f"Generated Password: {password}")

