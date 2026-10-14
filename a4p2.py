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

    # checks if the mode is valid
    if mode not in ["encrypt", "decrypt"]:
        raise ValueError(f"Invalid mode: {mode}. Must be 'encrypt' or 'decrypt'.")

    # when encrypting, it uses the normal alphabet as the source and the key as the target
    source_alpha, target_alpha = LETTERS, key.upper()

    # if we're decrypting, it uses the key as the source and the normal alphabet as the target
    if mode == "decrypt":
        source_alpha, target_alpha = key.upper(), LETTERS

    translated_parts = [] # this will hold pieces of encrypted/decrypyted text, as well as any unchanged characters

    # used Gemini for line 69
    # splits the message while keeping spaces, tabs, and newlines.
    # r"" preserves the backlash, \s matches whitespace characters, + matches one or more of the preceding thing
    message_parts = re.split(r"(\s+)", message) 

    for part in message_parts: # goes through the message we just split

        # checks if "part" is an empty string or a string that's only whitespace
        # If it is then it appends it to the translated list and continues to the next iteration of the loop
        if part == "" or part.isspace():
            translated_parts.append(part)
            continue

        # we define the start and end of the word in "part" so that we can separate the actual word from any surrounding punctuation or whitespace 
        word_start = 0
        word_end = len(part)

       # used Gemini for lines 85-90
       # this runs while there are still characters in the string to check and the character at the start index isn't a letter or number (so if it's punctuation or whitespace) 
        while word_start < word_end and not part[word_start].isalnum():
            word_start += 1 # goes to the next character if the current character isn't a letter or number

        # this runs while there are still characters in the string to check and the character before the end isn't a letter or number)
        while word_end > word_start and not part[word_end - 1].isalnum():
            word_end -= 1 # continues left until it finds a letter or number, then stops. This is the end of the actual word in "part"

        # separate the content from its surrounding characters.
        actual_word = part[word_start:word_end].lower() # gets all the characters for the actual word in "part" and converts it to lowercase to match with codebook
        prefix = part[:word_start] # gets everything before the actual word in "part"
        suffix = part[word_end:] # gets everything after the actual word in "part"

        codebook_replacement = None # used to track if a replacement has been found for the actual word in "part"

        if mode == "encrypt":

            for word in codebook:

                # if we find a match for the actual word in the codebook, we randomly choose one of its symbols to replace it with
                if actual_word == word.lower():
                    symbols = codebook[word]
                    codebook_replacement = str(random.choice(symbols))
                    break # stops searching because we found a match and don't need to check the rest of the codebook

        else: # this runs if we're decrypting

            for word in codebook:

                for symbol in codebook[word]: # looks at all the symbols associated with the current word

                    # if the message matches a symbol in the codebook, we replace it with the corresponding word
                    if actual_word == str(symbol):
                        codebook_replacement = word
                        break

                # if we found a replacement then we can stop looking
                if codebook_replacement is not None:
                    break

        # if we found a replacement in the codebook, we add it to the translated parts list with its surrounding characters and continue to the next iteration of the loop
        if codebook_replacement is not None:
            translated_parts.append(prefix + codebook_replacement + suffix) # for example --> '"' + 'Albert' + '!"'
            continue

        substituted_characters = [] # this will hold the current piece's processed characters

        for char in part: # goes through al the characters in the original piece

            upper_char = char.upper()

            # if the character is in the source alphabet, we find its index and get the corresponding character from the target alphabet
            if upper_char in source_alpha:
                index = source_alpha.index(upper_char)
                new_char = target_alpha[index]

                # to preserve the original case of the chracter (like if it was lowercase or uppercase)
                if char.islower():
                    new_char = new_char.lower()

                substituted_characters.append(new_char)

            else: # if the character isn't in the source alphabet, we just add it to the substituted characters list as is
                substituted_characters.append(char)

        translated_parts.append("".join(substituted_characters))

    return "".join(translated_parts)


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