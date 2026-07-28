#!/usr/bin/env python3
"""
security/secure_storage.py

Proposal Section 3.5 (Ethics) states: "Experimental data (flow statistics
logs, performance data and controller output) will all be stored in an
encrypted form on the researcher's local machine."

This was never implemented anywhere in the original build guide -- all
results CSVs were written in plaintext. This module encrypts/decrypts
results files using Fernet (symmetric AES-128-CBC + HMAC, via the
`cryptography` package), matching the plaintext ethics claim.

Usage:
    # one-time: generate and store a local key (keep this file private,
    # do not commit it to git or include it in your submission)
    python3 security/secure_storage.py --gen-key --key results/.secret.key

    # encrypt everything in results/ after an experiment run
    python3 security/secure_storage.py --encrypt-dir results/ --key results/.secret.key

    # decrypt a specific file back to plaintext for analysis
    python3 security/secure_storage.py --decrypt results/experiment_summary.csv.enc \\
        --key results/.secret.key
"""
import argparse
import glob
import os
from cryptography.fernet import Fernet

ENCRYPTED_EXT = ".enc"
PLAINTEXT_EXTENSIONS = (".csv", ".txt")


def generate_key(path):
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    os.chmod(path, 0o600)  # owner read/write only
    print(f"Generated key: {path} (chmod 600 -- keep this out of git/submission)")


def load_key(path):
    with open(path, "rb") as f:
        return f.read()


def encrypt_file(path, key, delete_plaintext=True):
    fernet = Fernet(key)
    with open(path, "rb") as f:
        data = f.read()
    token = fernet.encrypt(data)
    out_path = path + ENCRYPTED_EXT
    with open(out_path, "wb") as f:
        f.write(token)
    if delete_plaintext:
        os.remove(path)
    print(f"Encrypted: {path} -> {out_path}" + (" (plaintext removed)" if delete_plaintext else ""))


def decrypt_file(path, key, out_path=None):
    fernet = Fernet(key)
    with open(path, "rb") as f:
        token = f.read()
    data = fernet.decrypt(token)
    out_path = out_path or path[:-len(ENCRYPTED_EXT)]
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"Decrypted: {path} -> {out_path}")


def encrypt_dir(dir_path, key):
    targets = []
    for ext in PLAINTEXT_EXTENSIONS:
        targets.extend(glob.glob(os.path.join(dir_path, f"**/*{ext}"), recursive=True))
    if not targets:
        print(f"No plaintext {PLAINTEXT_EXTENSIONS} files found under {dir_path}")
        return
    for path in targets:
        encrypt_file(path, key)


def main():
    parser = argparse.ArgumentParser(description="Encrypt/decrypt experimental results at rest")
    parser.add_argument("--gen-key", action="store_true", help="generate a new Fernet key")
    parser.add_argument("--key", required=True, help="path to the key file")
    parser.add_argument("--encrypt-dir", help="encrypt every .csv/.txt file under this directory")
    parser.add_argument("--encrypt", help="encrypt a single file")
    parser.add_argument("--decrypt", help="decrypt a single .enc file")
    args = parser.parse_args()

    if args.gen_key:
        generate_key(args.key)
        return

    key = load_key(args.key)
    if args.encrypt_dir:
        encrypt_dir(args.encrypt_dir, key)
    elif args.encrypt:
        encrypt_file(args.encrypt, key)
    elif args.decrypt:
        decrypt_file(args.decrypt, key)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
