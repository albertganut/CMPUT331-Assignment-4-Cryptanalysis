#!/usr/bin/python3

#---------------------------------------------------------------
#
# CMPUT 331 Student Submission License
# Version 1.0
# Copyright 2026 Albert Ganut
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
CMPUT 331 Assignment 1 Student Solution
September 2026
Author: Albert Ganut
"""


from sys import flags

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def get_map(letters=LETTERS):
    char_to_index = {} # holds the letter (keys) that are mapped to their index (values)
    index_to_char = {} # holds the index (keys) that are mapped to their letter (values)

    for index in range(len(letters)):
        letter = letters[index] # gets the letter at whatever index we're on

        char_to_index[letter] = index # adding the letter to the dictionary with its index as the key
        index_to_char[index] = letter # adding the index to the dictionary with its letter as the key

    return char_to_index, index_to_char

def encrypt(message: str, key: str):
    message = message.upper()
    key = key.upper()

    char_to_index, index_to_char = get_map()

    encrypted_message = ""
    
    for char in message:

        if char in char_to_index: # if block runs if the current character is in the dictionary
            index = char_to_index[char]
            new_index = (index + char_to_index[key]) % len(LETTERS) # adding the index of the character to the index of the key and taking the mod
            encrypted_message += index_to_char[new_index]
        else: # the else block runs if it is not in the dictionary, meaning it is not in the alphabet
            encrypted_message += char

    return encrypted_message

def decrypt(message: str, key: str):
    message = message.upper()
    key = key.upper()

    char_to_index, index_to_char = get_map()

    decrypted_message = ""

    for char in message:

        if char in char_to_index:
            index = char_to_index[char]
            new_index = (index - char_to_index[key]) % len(LETTERS) # subtract instead to shift the index back
            decrypted_message += index_to_char[new_index]
        else:
            decrypted_message += char

    return decrypted_message


def test():
    global SHIFTDICT, LETTERDICT 
    SHIFTDICT, LETTERDICT = get_map()
    assert decrypt(encrypt("FOO", "G"), "G") == "FOO"


if __name__ == "__main__" and not flags.interactive:
    test()