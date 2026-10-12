#!/usr/bin/env python3

#---------------------------------------------------------------
#
# CMPUT 331 Student Submission License
# Version 1.0
# Copyright October 8, 2026 Albert Ganut
#
# Redistribution is forbidden in all circumstances. Use of this software
# without explicit authorization from the author is prohibited.
#
# This software was produced as a solution for an assignment in the course
# CMPUT 331 - Computational Cryptography at the University of
# Alberta, Canada. This solution is confidential and remains confidential 
# after it is submitted for grading.
#
# Copying any part of this solution without including this copyright notice
# is illegal.
#
# If any portion of this software is included in a solution submitted for
# grading at an educational institution, the submitter will be subject to
# the sanctions for plagiarism at that institution.
#
# If this software is found in any public website or public repository, the
# person finding it is kindly requested to immediately report, including 
# the URL or other repository locating information, to the following email
# address:
#
#          gkondrak <at> ualberta.ca
#
#---------------------------------------------------------------

"""
Nomenclator cipher
Author: Albert Ganut
"""

import re
import random

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def translateMessage(key: str, message: str, codebook: dict, mode: str):
    """
    Encrypt or decrypt using a nomenclator.
    Takes a substitution cipher key, a message (plaintext or ciphertext),
    a codebook dictionary, and a mode string ('encrypt' or 'decrypt')
    specifying the action to be taken. Returns a string containing the
    ciphertext (if encrypting) or plaintext (if decrypting).
    """

    # checks if the mode we're trying is valid
    if mode not in ["encrypt", "decrypt"]:
        raise ValueError(f"Invalid mode: {mode}. Must be 'encrypt' or 'decrypt'.")

    # two dictionaries to map words to symbols and symbols to words 
    word_to_symbols = {}
    symbols_to_word = {}

    for word in codebook:

        word_to_symbols[word.lower()] = codebook[word]

        for symbol in codebook[word]:

            symbols_to_word[str(symbol)] = word

    source = LETTERS
    target = key.upper()

    if mode == "decrypt":
        source, target = key.upper(), LETTERS

    translated = []

    # splits the message while keeping the whitespace so spaces, tabs, and newlines aren't changed
    parts = re.split(r"(\s+)", message)

    for part in parts:

        if part == "" or part.isspace():
            translated.append(part)
            continue

        start = 0
        end = len(part)

        while start < end and not part[start].isalnum():

            start += 1

        while end > start and not part[end - 1].isalnum():

            end -= 1

        # dividing the word into three parts
        actual_word = part[start:end].lower()
        prefix = part[:start]
        suffix = part[end:]

        replace = None

        if mode == "encrypt":
            if actual_word in word_to_symbols:
                symbols = word_to_symbols[actual_word]
                replace = str(random.choice(symbols))
        else:
            if actual_word in symbols_to_word:
                replace = symbols_to_word[actual_word]

        if replace is not None:
            translated.append(prefix + replace + suffix)
            continue

        simple_sub_letters = []

        for char in part:

            upper_char = char.upper()

            if upper_char in source:
                index = source.index(upper_char)
                new_char = target[index]

                if char.islower():
                    new_char = new_char.lower()

                simple_sub_letters.append(new_char)
            else:

                simple_sub_letters.append(char)

        translated.append(''.join(simple_sub_letters))

    return ''.join(translated)


def encryptMessage(key: str, message: str, codebook: dict):
    return translateMessage(key, message, codebook, 'encrypt')


def decryptMessage(key: str, message: str, codebook: dict):
    return translateMessage(key, message, codebook, 'decrypt')


def test():
    # Provided tests.
    key = 'LFWOAYUISVKMNXPBDCRJTQEGHZ'
    plaintext = "X-ray machines cannot be brought here, as -ray* are very dangerous. Hello;ray! ray;"
    codebook = {'ray':['1']}
    ciphertext = encryptMessage(key, plaintext, codebook)
    assert ciphertext=="G-clh nlwisxar wlxxpj fa fcptuij iaca, lr -1* lca qach olxuacptr. Iammp;clh! 1;"
    # End of provided tests.

if __name__ == '__main__':
    test()
