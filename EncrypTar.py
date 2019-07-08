#!/usr/bin/env python3
# Encrypted Tar (EncrypTar)
# Author: Tom Conroy

# imports
import hashlib
from Crypto.Cipher import AES
import tarfile as tar
import argparse
import getpass
import os, io, os.path
from enum import Enum

SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 16

MAGIC_BYTES = b'\x25\x24'

class EncrypTarMode(Enum):
    ARCHIVE = 0
    EXTRACT = 1
    LIST = 2

def CreateTar(files, recursive, current_directory, no_compression):
    tar_buffer = io.BytesIO()
    if no_compression:
        compression_mode = 'w:'
    else:
        compression_mode = 'w:xz' # use lzma compression
    tar_file = tar.open(mode=compression_mode, fileobj=tar_buffer) # write a tarfile to the buffer
    for file in files:
        os.chdir(current_directory)
        if os.path.isfile(file):
            directory, filename = os.path.split(file)
            if directory != '':
                os.chdir(directory) # make all files placed relative to the source directory
            tar_file.add(filename, recursive=recursive)
        else:
            os.chdir(file)
            tar_file.add('.', recursive=recursive)

    tar_file.close()
    tar_data = tar_buffer.getvalue()
    return tar_data

def DeriveKey(passphrase, salt):
    return hashlib.pbkdf2_hmac('sha256', bytearray(passphrase, 'utf-8'), salt, 100000)

def Encrypt(archive, key, nonce):
    aesObj = AES.new(key, AES.MODE_GCM, nonce)
    ciphertext, tag = aesObj.encrypt_and_digest(archive)
    return ciphertext, tag

def RestoreTar(archive, directory):
    tar_buffer = io.BytesIO(archive)
    tar_file = tar.open(mode='r:*', fileobj=tar_buffer)
    tar_file.extractall(path=directory)

def Decrypt(archive, key, nonce, tag):
    aesObj = AES.new(key, AES.MODE_GCM, nonce)
    try:
        plaintext = aesObj.decrypt_and_verify(archive, tag)
    except ValueError:
        raise ValueError("""Decryption failed.
Either the passphrase was incorrect or the archive has been corrupted.""")
    return plaintext

def DecryptEncrypTarFile(archive_filename, passphrase):
    with open(archive_filename, 'rb') as archive_file:
        if archive_file.read(2) != MAGIC_BYTES:
            raise ValueError(archive_filename + " is not an EncrypTar file.")
        salt = archive_file.read(SALT_LEN)
        key = DeriveKey(passphrase, salt)
        nonce = archive_file.read(NONCE_LEN)
        tag = archive_file.read(TAG_LEN)
        enc_archive = archive_file.read()
    archive = Decrypt(enc_archive, key, nonce, tag)
    return archive

def WriteArchive(archive_filename, salt, nonce, enc_archive, tag):
    with open(archive_filename, 'wb') as archive_file:
        archive_file.write(MAGIC_BYTES)
        archive_file.write(salt)
        archive_file.write(nonce)
        archive_file.write(tag)
        archive_file.write(enc_archive)

def ListTar(archive):
    tar_buffer = io.BytesIO(archive)
    tar_file = tar.open(mode='r:*', fileobj=tar_buffer)
    tar_file.list()

def RunEncrypTar():

    # setup commandline argument parsing using argparse module
    parser = argparse.ArgumentParser(description='Python script that does encrypted archives of both files and directories.')
    parser.add_argument("ARCHIVE", help='Name of archive file to create/restore.')
    parser.add_argument("FILES", nargs='*', default=['.'], help='The file/directory to archive/(extract to). Not recursive by default. Defaults to current working directory.')
    parser.add_argument('-p', '--passphrase', help='Optional file containing passphrase to use for encryption.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-a', '--archive', action='store_true', help='Run in archive mode, default mode.')
    group.add_argument('-x', '--extract', action='store_true', help='Run in extract mode.')
    group.add_argument('-l', '--list', action='store_true', help='Lists the contents of an archive.')
    parser.add_argument('-r', '--recursive', action='store_true', help='Encrypt directories recursively.')
    parser.add_argument('-n', '--no-compression', action='store_true', help='Do not use compression (lzma is default) when creating the archive.')
    args = parser.parse_args()

    current_directory = os.getcwd()

    if args.extract:
        mode = EncrypTarMode.EXTRACT
        if len(args.FILES) > 1:
            raise ValueError("Please specify only one extract directory.")
    elif args.list:
        mode = EncrypTarMode.LIST
    else:
        mode = EncrypTarMode.ARCHIVE

    if args.passphrase:
        with open(args.passphrase, 'r') as passphrase_file:
            passphrase = passphrase_file.read().strip()
    else:
        passphrase = getpass.getpass('Encryption Passphrase: ')

    recursive = False
    if args.recursive:
        recursive = True

    if mode == EncrypTarMode.ARCHIVE:
        for file in args.FILES:
            if not os.path.isfile(file) and not os.path.isdir(file):
                raise ValueError("The file/directory " + file + " must exist for it to be archived!")

        salt = os.urandom(SALT_LEN) # get a salt for key derivation
        key = DeriveKey(passphrase, salt)
        archive = CreateTar(args.FILES, recursive, current_directory, args.no_compression)
        nonce = os.urandom(NONCE_LEN) # create a nonce for AES encryption
        enc_archive, tag = Encrypt(archive, key, nonce)
        os.chdir(current_directory)
        WriteArchive(args.ARCHIVE, salt, nonce, enc_archive, tag)

    elif mode == EncrypTarMode.EXTRACT:
        if not os.path.isdir(args.FILES[0]):
            raise ValueError("The extraction location must be a directory")
        archive = DecryptEncrypTarFile(args.ARCHIVE, passphrase)
        RestoreTar(archive, args.FILES[0])

    else: # mode == EncrypTarMode.LIST
        archive = DecryptEncrypTarFile(args.ARCHIVE, passphrase)
        ListTar(archive)

if __name__ == "__main__":
    try:
        RunEncrypTar()
    except ValueError as e:
        print(e)
