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
#----------------------------------------------------------------

#-------------------- START ASSIGNMENT HERE ---------------------
"""
General decryption program
Author: Albert Ganut
"""

from detectEnglish import isEnglish
from itertools import permutations
from cryptomath import gcd, findModInverse
from a1p1 import decrypt as decrypt_caesar
from a2p3 import decipherMessage as decrypt_transposition
from string import ascii_uppercase as uppercase_alpha_letters # ABCDEFGHIJKLMNOPQRSTUVWXYZ

def hack_caesar(ciphertext):

    for key in uppercase_alpha_letters:  # uses brute force to try all letters in the English alphabet as keys

        decrypted = decrypt_caesar(ciphertext, key)
        
        if isEnglish(decrypted, wordPercentage=50, letterPercentage=70): 
            return decrypted

    return None # returns None if no valid decryption is found  

def hack_transposition(ciphertext):

    for len_key in range(1, 10): # tests all key lengths of 1 col up to 9 cols

        for key_permutation in permutations(range(1, len_key + 1)): # generates all possible permutations of the key of those col numbers
            decrypted = decrypt_transposition(list(key_permutation), ciphertext) # converts the tuple of different key permutations into a list to be used in the decryption function()

            if isEnglish(decrypted, wordPercentage=50, letterPercentage=70):
                return decrypted 

    return None # returns None if no valid decryption is found

def hack_affine(ciphertext):

    modulus = len(uppercase_alpha_letters) 

    for key_multiplier in range(1, modulus): # tests all possible key multipliers from 1 to 25 

        # if the gcd of the key multiplier and the modulus isn't 1 then then a mod inverse doesn't exist and the rest of the code is skipped for that key multiplier. It goes to the next iteration
        if gcd(key_multiplier, modulus) != 1:
            continue

        mod_inverse = findModInverse(key_multiplier, modulus)  

        for key_shift in range(modulus): # tests all possible key shifts from 0 to 25

            decrypted = "" # this will store the decrypted message later

            for char in ciphertext:

                if char.upper() in uppercase_alpha_letters:
                    letter_index = uppercase_alpha_letters.index(char.upper()) # gets the index of the letter 
                    decrypted_index = (mod_inverse * (letter_index - key_shift)) % modulus # gets the index of the decrypted letter using the affine decryption formula
                    decrypted_letter = uppercase_alpha_letters[decrypted_index] # gets the actual letter from the decrypted index

                    # if the original letter from the ciphertext was lowercase, then the decrypted letter is also converted to lowercase. Otherwise, we keep and add it as an uppercase letter
                    if char.islower(): 
                        decrypted += decrypted_letter.lower()
                    else:
                        decrypted += decrypted_letter

                else: # if the char isn't a letter, then we just add it to the decrypted message as is
                    decrypted += char

            if isEnglish(decrypted, wordPercentage=50, letterPercentage=70):
                return decrypted

    return None

def hack(ciphertype: str, ciphertext: str):
    """
    Decrypt a given ciphertext with either of these algorithm: caesar, transposition, or affine.
        Input: a line from `ciphers.txt`.
        Output: the decrypted message (or plaintext).
    """

    if ciphertype == "C":
        result = hack_caesar(ciphertext)

    elif ciphertype == "T":
        result = hack_transposition(ciphertext)

    elif ciphertype == "A":
        result = hack_affine(ciphertext)

    else:
        result = None

    if result:
        return result
    
    else:
        return ciphertext  # return the original ciphertext if no decryption was successful

def processing():

    with open("ciphers.txt", "r") as file:
        lines = file.readlines()

        plaintexts = []

        for line in lines:

            ciphertype, ciphertext = line.rstrip('\r\n').split(";", 1)  # split the line into cipher type and ciphertext
            plaintext = hack(ciphertype, ciphertext)  # decrypt the ciphertext using the appropriate hack function
            plaintexts.append(plaintext)  # add the decrypted plaintext to the list

    with open("decrypted.txt", "w") as file:
        for plaintext in plaintexts:

            file.write(plaintext + "\n")  # write each decrypted plaintext to the output file

def test():
    # Test cases for the hack function. You can add more tests as needed.
    assert hack("C", "GHGIQ") == "ABACK", "Caesar hack failed"
    assert hack("T", "IS HAUCREERNP F") == "CIPHERS ARE FUN", "Transposition hack failed"
    assert hack("A", "IHHWVC SWFRCP") == "AFFINE CIPHER", "Affine hack failed"
    assert hack("A", "XBQUVSQVFRUVLE FVSOTG") == "MULTIPLICATION CIPHER", "Affine hack failed"

if __name__ == '__main__':
    test()
    processing()