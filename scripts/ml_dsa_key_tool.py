#!/usr/bin/env python3
"""Utility to encrypt ML-DSA private keys with a password.

This tool encrypts ML-DSA private keys using AES-256-GCM encryption,
making them safer to store on disk.
"""

import argparse
import getpass
import pathlib
import sys

# Add src to path for direct execution
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))

from model_signing._signing.sign_ml_dsa import encrypt_private_key, decrypt_private_key, _ENCRYPTED_KEY_HEADER


def encrypt_key(input_path: pathlib.Path, output_path: pathlib.Path, password: str) -> None:
    """Encrypt an ML-DSA private key.

    Args:
        input_path: Path to the raw private key.
        output_path: Path to save the encrypted key.
        password: Password for encryption.
    """
    # Read raw key
    raw_key = input_path.read_bytes()

    # Check if already encrypted
    if raw_key.startswith(_ENCRYPTED_KEY_HEADER):
        print(f"Error: {input_path} is already encrypted", file=sys.stderr)
        sys.exit(1)

    # Encrypt
    encrypted_key = encrypt_private_key(raw_key, password)

    # Write encrypted key
    output_path.write_bytes(encrypted_key)

    print(f"✓ Key encrypted successfully")
    print(f"  Input:  {input_path} ({len(raw_key)} bytes)")
    print(f"  Output: {output_path} ({len(encrypted_key)} bytes)")
    print(f"  Overhead: {len(encrypted_key) - len(raw_key)} bytes")


def decrypt_key(input_path: pathlib.Path, output_path: pathlib.Path, password: str) -> None:
    """Decrypt an ML-DSA private key.

    Args:
        input_path: Path to the encrypted key.
        output_path: Path to save the decrypted key.
        password: Password for decryption.
    """
    # Read encrypted key
    encrypted_key = input_path.read_bytes()

    # Check if encrypted
    if not encrypted_key.startswith(_ENCRYPTED_KEY_HEADER):
        print(f"Error: {input_path} is not encrypted", file=sys.stderr)
        sys.exit(1)

    # Decrypt
    try:
        raw_key = decrypt_private_key(encrypted_key, password)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Write decrypted key
    output_path.write_bytes(raw_key)

    print(f"✓ Key decrypted successfully")
    print(f"  Input:  {input_path} ({len(encrypted_key)} bytes)")
    print(f"  Output: {output_path} ({len(raw_key)} bytes)")


def verify_key(key_path: pathlib.Path, password: str | None = None) -> None:
    """Verify an ML-DSA key (encrypted or raw).

    Args:
        key_path: Path to the key to verify.
        password: Password if the key is encrypted.
    """
    key_data = key_path.read_bytes()

    is_encrypted = key_data.startswith(_ENCRYPTED_KEY_HEADER)

    print(f"Key: {key_path}")
    print(f"Size: {len(key_data)} bytes")
    print(f"Encrypted: {'Yes' if is_encrypted else 'No'}")

    if is_encrypted:
        if password is None:
            print("Status: Cannot verify without password")
        else:
            try:
                raw_key = decrypt_private_key(key_data, password)
                print(f"Status: ✓ Valid encrypted key")
                print(f"Raw key size: {len(raw_key)} bytes")

                # Try to determine variant from size
                variant_map = {
                    2560: "ML_DSA_44",
                    4032: "ML_DSA_65",
                    4896: "ML_DSA_87",
                }
                variant = variant_map.get(len(raw_key), "Unknown")
                print(f"Detected variant: {variant}")
            except ValueError as e:
                print(f"Status: ✗ {e}")
    else:
        print("Status: ✓ Valid raw key")
        # Try to determine variant from size
        variant_map = {
            2560: "ML_DSA_44",
            4032: "ML_DSA_65",
            4896: "ML_DSA_87",
        }
        variant = variant_map.get(len(key_data), "Unknown")
        print(f"Detected variant: {variant}")


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt/decrypt ML-DSA private keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a key
  %(prog)s encrypt my_key.priv my_key.enc

  # Decrypt a key
  %(prog)s decrypt my_key.enc my_key.priv

  # Verify a key
  %(prog)s verify my_key.enc
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a private key")
    encrypt_parser.add_argument("input", type=pathlib.Path, help="Raw private key file")
    encrypt_parser.add_argument("output", type=pathlib.Path, help="Output encrypted key file")
    encrypt_parser.add_argument("--password", type=str, help="Password (will prompt if not provided)")

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a private key")
    decrypt_parser.add_argument("input", type=pathlib.Path, help="Encrypted key file")
    decrypt_parser.add_argument("output", type=pathlib.Path, help="Output raw key file")
    decrypt_parser.add_argument("--password", type=str, help="Password (will prompt if not provided)")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a key file")
    verify_parser.add_argument("key", type=pathlib.Path, help="Key file to verify")
    verify_parser.add_argument("--password", type=str, help="Password (for encrypted keys)")

    args = parser.parse_args()

    if args.command == "encrypt":
        if not args.input.exists():
            print(f"Error: Input file {args.input} not found", file=sys.stderr)
            sys.exit(1)

        if args.output.exists():
            response = input(f"Warning: {args.output} exists. Overwrite? [y/N] ")
            if response.lower() != 'y':
                print("Aborted")
                sys.exit(0)

        password = args.password or getpass.getpass("Enter password: ")
        password2 = args.password or getpass.getpass("Confirm password: ")

        if password != password2:
            print("Error: Passwords do not match", file=sys.stderr)
            sys.exit(1)

        encrypt_key(args.input, args.output, password)

    elif args.command == "decrypt":
        if not args.input.exists():
            print(f"Error: Input file {args.input} not found", file=sys.stderr)
            sys.exit(1)

        if args.output.exists():
            response = input(f"Warning: {args.output} exists. Overwrite? [y/N] ")
            if response.lower() != 'y':
                print("Aborted")
                sys.exit(0)

        password = args.password or getpass.getpass("Enter password: ")
        decrypt_key(args.input, args.output, password)

    elif args.command == "verify":
        if not args.key.exists():
            print(f"Error: Key file {args.key} not found", file=sys.stderr)
            sys.exit(1)

        password = args.password
        if password is None:
            # Check if encrypted
            key_data = args.key.read_bytes()
            if key_data.startswith(_ENCRYPTED_KEY_HEADER):
                password = getpass.getpass("Enter password (or press Enter to skip): ")
                if not password:
                    password = None

        verify_key(args.key, password)


if __name__ == "__main__":
    main()
