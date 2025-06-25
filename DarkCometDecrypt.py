"""
RC4 Decryption Script

Author: Alessandro Salucci
Date: 20.05.2025
Description:
    This script reads a file containing hexadecimal-encoded data.
    Each line of the file is processed by first converting it from hex to bytes,
    calculating its SHA-256 hash (to verify data integrity),
    and then decrypting the byte data using the RC4 algorithm with a provided passphrase.
    Finally, the results (original hex, decoded bytes, SHA-256 hash, and decrypted text)
    are saved into a CSV file for easy analysis.

    This script is part of the Cyber Security Analyst (Incident Response) assessment
    by Avantec (Immersive Labs).

Requirements:
    - Python 3.x
    - pycryptodome library (install with `pip install pycryptodome`)

Usage:
    Run the script and enter the path to the input file when prompted.
"""

# Import required libraries
import os            # Used to handle file paths and check if files exist
import csv           # Used to write data into CSV files
import hashlib       # Used to calculate SHA-256 hash values
from Crypto.Cipher import ARC4  # Library providing RC4 encryption and decryption functionality


def decode_and_hash(input_string: str):
    """
    Converts a hexadecimal-encoded string into bytes, then tries to decode these bytes into readable text,
    and calculates the SHA-256 hash of the original bytes for data verification.

    :param input_string: A string containing hexadecimal characters
    :return: A tuple containing the decoded text (if possible) and its SHA-256 hash value
    """
    try:
        decoded_bytes = bytes.fromhex(input_string)  # Converts hex string to raw bytes
        decoded_text = decoded_bytes.decode(errors='ignore')  # Converts bytes to text, ignoring undecodable parts
        sha256_hash = hashlib.sha256(decoded_bytes).hexdigest().upper()  # Generates SHA-256 hash in uppercase hex format
        return decoded_text, sha256_hash
    except ValueError:  # Handles cases where input is not valid hex
        return None, None


def decrypt_rc4(hex_input: str, passphrase: str):
    """
    Decrypts RC4-encrypted data that is provided in hexadecimal format.

    :param hex_input: RC4-encrypted data as a hexadecimal string
    :param passphrase: The RC4 key used for decryption
    :return: The decrypted text decoded in Latin-1 encoding
    """
    try:
        input_bytes = bytes.fromhex(hex_input)  # Converts hex string into bytes
        cipher = ARC4.new(passphrase.encode('utf-8'))  # Creates an RC4 cipher object using the given passphrase
        decrypted_bytes = cipher.decrypt(input_bytes)  # Decrypts the byte data using RC4
        return decrypted_bytes.decode('latin1', errors='ignore')  # Converts decrypted bytes into readable Latin-1 text
    except ValueError:  # Handles invalid hexadecimal inputs
        return None


def process_file(input_file_path: str, output_csv_path: str, passphrase: str):
    """
    Processes an input file line by line, decodes each line from hex, hashes it,
    decrypts the result, and saves all this data into a CSV file.

    :param input_file_path: Path of the file containing hexadecimal-encoded data
    :param output_csv_path: Path of the CSV file where results will be saved
    :param passphrase: RC4 decryption key
    """
    results = []  # Initializes an empty list to store results from processing each line

    try:
        with open(input_file_path, "r", encoding="utf-8") as file:  # Opens the input file for reading
            for line in file:  # Processes each line in the file one by one
                input_data = line.strip()  # Removes leading/trailing whitespace and newlines
                if not input_data:
                    continue  # Skips processing if the line is empty

                decoded_text, sha256_hash = decode_and_hash(input_data)  # Decodes and hashes the input data
                if decoded_text is None:
                    continue  # Skips the line if it cannot be decoded

                decrypted_text = decrypt_rc4(decoded_text, passphrase)  # Decrypts the decoded text using RC4

                # Adds the original hex data, decoded bytes, hash, and decrypted text to results
                results.append([input_data, decoded_text, sha256_hash, decrypted_text])

        # Opens a CSV file for writing the results
        with open(output_csv_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)  # Creates a CSV writer object
            writer.writerow(["Original Value", "Decoded Bytes", "SHA-256 Hash", "Decrypted Text (Latin1)"])  # Writes the header row
            writer.writerows(results)  # Writes all stored result rows into the CSV file

        print(f"Results successfully saved to: {output_csv_path}")  # Notifies the user of successful operation
    except Exception as e:  # Catches and reports any errors that occur during file processing
        print(f"An error occurred during file processing: {e}")


def main():
    """
    The main function that controls the execution flow of the script.
    Asks the user for the file path, checks if the file exists,
    and then processes the file content using the provided RC4 key.
    """
    passphrase = "#KCMDDC51#-890"  # Defines the RC4 decryption key

    input_file_path = input("Please enter the path to the input file: ").strip()  # Prompts user for input file path

    if not os.path.isfile(input_file_path):  # Checks if the entered file exists
        print("Error: The specified file does not exist!")  # Notifies the user if file is missing
        return

    # Determines the path of the CSV file for output, placing it next to the input file
    output_csv_path = os.path.join(os.path.dirname(input_file_path), "decryption_results.csv")

    # Initiates processing of the input file
    process_file(input_file_path, output_csv_path, passphrase)


if __name__ == "__main__":  # Ensures this script runs only when executed directly, not when imported
    main()