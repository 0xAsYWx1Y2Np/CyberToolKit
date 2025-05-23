"""
RC4 Decryption Script

Author: Alessandro Salucci
Date: 20.05.2025
Description: 
    This script reads a file containing hexadecimal-encoded data, decodes it, 
    computes a SHA-256 hash, and decrypts it using the RC4 algorithm with a given passphrase.
    The results are saved in a CSV file.

    The script is part of the assessment - Cyber Security Analyst (Incident Response) by Avantec (Immersive Labs)

Requirements:
    - Python 3.x
    - pycryptodome library (install with `pip install pycryptodome`)

Usage:
    Run the script and provide the input file path when prompted.
"""

import os
import csv
import hashlib
from Crypto.Cipher import ARC4

def decode_and_hash(input_string: str):
    """
    Decodes a hexadecimal string, computes its SHA-256 hash, and returns the decoded bytes as a string.
    
    :param input_string: Hexadecimal-encoded string
    :return: Tuple containing decoded string and SHA-256 hash
    """
    try:
        decoded_bytes = bytes.fromhex(input_string)
        decoded_text = decoded_bytes.decode(errors='ignore')
        sha256_hash = hashlib.sha256(decoded_bytes).hexdigest().upper()
        return decoded_text, sha256_hash
    except ValueError:
        return None, None

def decrypt_rc4(hex_input: str, passphrase: str):
    """
    Decrypts an RC4-encrypted hexadecimal input using the given passphrase.
    
    :param hex_input: Hexadecimal-encoded RC4 encrypted string
    :param passphrase: Passphrase for decryption
    :return: Decrypted text in Latin-1 encoding
    """
    try:
        input_bytes = bytes.fromhex(hex_input)
        cipher = ARC4.new(passphrase.encode('utf-8'))
        decrypted_bytes = cipher.decrypt(input_bytes)
        return decrypted_bytes.decode('latin1', errors='ignore')
    except ValueError:
        return None

def process_file(input_file_path: str, output_csv_path: str, passphrase: str):
    """
    Reads an input file line by line, decodes, hashes, decrypts, and writes results to a CSV file.
    
    :param input_file_path: Path to the input file containing hexadecimal-encoded data
    :param output_csv_path: Path where the CSV results will be saved
    :param passphrase: Passphrase for RC4 decryption
    """
    results = []
    
    try:
        with open(input_file_path, "r", encoding="utf-8") as file:
            for line in file:
                input_data = line.strip()
                if not input_data:
                    continue
                
                decoded_text, sha256_hash = decode_and_hash(input_data)
                if decoded_text is None:
                    continue
                
                decrypted_text = decrypt_rc4(decoded_text, passphrase)
                results.append([input_data, decoded_text, sha256_hash, decrypted_text])
        
        with open(output_csv_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Original Value", "Decoded Bytes", "SHA-256 Hash", "Decrypted Text (Latin1)"])
            writer.writerows(results)
        
        print(f"Results saved to: {output_csv_path}")
    except Exception as e:
        print(f"Error processing file: {e}")

def main():
    """ Main function to execute the script. """
    passphrase = "#KCMDDC51#-890"
    
    input_file_path = input("Please enter the path to the input file: ").strip()
    if not os.path.isfile(input_file_path):
        print("Error: File not found!")
        return
    
    output_csv_path = os.path.join(os.path.dirname(input_file_path), "decryption_results.csv")
    process_file(input_file_path, output_csv_path, passphrase)

if __name__ == "__main__":
    main()