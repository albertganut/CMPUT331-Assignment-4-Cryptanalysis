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
Enhanced substitution cipher solver
Author: Albert Ganut
"""

import re
import simpleSubHacker as ssh
from detectEnglish import loadDictionary

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def is_word_valid(cipherword, candidate, letter_mapping):
    """
    this function checks if the candidate word can decrypt the cipherword without breaking the current letter mapping or 
creating any conflicting letter assignments. It returns True if the candidate is valid and False if it is not.
    """

    cipherword = cipherword.upper() # this is the encrypted word that we're checking
    candidate = candidate.upper() # this is a dictionary word that might be its plaintext

    cipher_to_plaintext = {} # temporarily stores already-solved letter pairs and proposed pairs from this candidate --> this does not change letter_mapping.

    for cipher_letter in LETTERS:

        possible_letters = letter_mapping[cipher_letter]

        # checks if the letter has only one possible mapping, if so it adds it to the cipher_to_plaintext dict
        if len(possible_letters) == 1:
            plaintext_letter = possible_letters[0] # gets the only item in the list in pos 0 --> this is then a solved plaintext letter

            # checks if the plaintext letter is already in the cipher_to_plaintext dict, if so it returns False because that means that two different cipher letters are 
            # mapping to the same plaintext letter --> rejects the candidate word
            if plaintext_letter in cipher_to_plaintext.values():

                return False

            cipher_to_plaintext[cipher_letter] = plaintext_letter # adds the solved pair into the temp dict

    for index in range(len(cipherword)):

        # getting the letters at the current index of the cipherword and candidate word
        ciphertext_letter = cipherword[index]
        plaintext_letter = candidate[index]

        possible_letters = letter_mapping[ciphertext_letter]

        # checks if there are known possioble letters
        # rejects the candidate if its plaintext letter is not one of them
        if len(possible_letters) > 0:
            if plaintext_letter not in possible_letters:

                return False
        # checks if the current ciphertext letter has already been assigned in the temp dict
        # if the current assignment is different than the one in the temp dict, it rejects the candidate
        if ciphertext_letter in cipher_to_plaintext:
            if cipher_to_plaintext[ciphertext_letter] != plaintext_letter:

                return False


        for current_ciphertext_letter in cipher_to_plaintext:

            existing_plaintext_letter = cipher_to_plaintext[current_ciphertext_letter] # gets the plaintext letter assigned to each key

            # checks if a different ciphertext letter already uses this plaintext letter.
            # if so, it rejects the candidate because two different ciphertext letters cannot map to the same plaintext letter.
            if existing_plaintext_letter == plaintext_letter:
                if current_ciphertext_letter != ciphertext_letter:

                    return False

        cipher_to_plaintext[ciphertext_letter] = plaintext_letter # if everything passes then it gets added as a valid pair to the temp dict

    return True


def hackSimpleSub(message: str):
    """
    Simple substitution cipher hacker.
    First runs the textbook program to get an initial, potentially incomplete decipherment.
    Then uses regular expressions and a dictionary to decipher additional letters.
    """

    dictionary_words = loadDictionary() # using the loadDictionary function from detectEnglish.py to get a dictionary of words, with each word stored as a dictionary key
    letter_mapping = ssh.hackSimpleSub(message) # this gets the initial letter mapping from the simpleSubHacker.py 
    
    # used Gemini on line 121
    cipherwords = re.findall("[A-Z]+", message.upper()) # converts the message to uppercase and gets groups of A–Z letters

    unique_cipherwords = [] # this will hold the unique cipherwords from the message

    for cipherword in cipherwords:

        # if the current cipherword hasn't been added yet, then it adds it
        if cipherword not in unique_cipherwords:
            unique_cipherwords.append(cipherword)

    while True:

        decryption_complete = True

        for cipherword in unique_cipherwords:

            for ciphertext_letter in cipherword:

                # chhecks if the current ciphertext letter does not have exactly one possible plaintext letter
                # if so, it means the letter is not fully deciphered
                if len(letter_mapping[ciphertext_letter]) != 1:
                    decryption_complete = False

                    break

            # if an unsolved letter was found, stops checking the remaining words
            if not decryption_complete:

                break

        # used Gemini for lines 153-155
        #  if we were able to fully decipher the message, then we return the decrypted message using the letter mapping as a string
        if decryption_complete:

            return ssh.decryptWithCipherletterMapping(message,letter_mapping)

        previous_mapping = {} # this will hold the previous letter mapping to check if the letter mapping has changed after each iteration

        for ciphertext_letter in LETTERS:
            
            previous_mapping[ciphertext_letter] = letter_mapping[ciphertext_letter].copy() # copies this letter's list of possible plaintext letters into previous_mapping

        for cipherword in unique_cipherwords:

            pattern_parts = [] # this will hold parts of the regex pattern for the current cipherword
            has_undeciphered_letter = False # assumes that the current cipherword has been fully deciphered

            for ciphertext_letter in cipherword:

                possible_letters = letter_mapping[ciphertext_letter] # gets the current list of possible plaintext letters for the current ciphertext letter

                # if there is only one possible letter, it means the ciphertext letter has been fully deciphered
                # adds the deciphered letter to the pattern_parts list
                if len(possible_letters) == 1:
                    plaintext_letter = possible_letters[0]
                    pattern_parts.append(plaintext_letter)

                # if there are multiple possible letters, it means the ciphertext letter has not been fully deciphered
                # combines the possible letters into a pattern for the regex to use
                # Ex: possible_letters = ["A", "B"] adds "[AB]" to pattern_parts
                elif len(possible_letters) > 1:
                    pattern_parts.append("[" + "".join(possible_letters) + "]")
                    has_undeciphered_letter = True

                # if no possible letters are known, the ciphertext letter is still unsolved
                # makes a regex pattern that allows any uppercase A–Z letter at this position
                else:
                    pattern_parts.append("[A-Z]")
                    has_undeciphered_letter = True

            # if the current cipherword has no undeciphered letters, it means that it has been fully deciphered and we just stop right here and
            # move on to the next cipherword
            if not has_undeciphered_letter:

                continue

            # used Gemini for line 198
            word_pattern = re.compile("".join(pattern_parts)) # combines all the parts into a string to use for regex matching. Ex: pattern_parts = ["A", "L", "B", "E", "R", "T", "[A-Z]"] --> ALBERT[A-Z]
            valid_candidates = [] 

            for candidate in dictionary_words: # goes through all the words returned by loadDictionary()

                # used Gemini for lines 206-208
                # if the length of the current word is not the same as the length of the current cipherword or if the current word does not match the regex pattern
                # then it skips to the next candidate word
                if len(candidate) != len(cipherword) or word_pattern.fullmatch(candidate) is None:

                    continue

                # if the candidate follows the current letter mapping and has no conflicting letter assignments, then it adds the candidate to the valid_candidates list
                if is_word_valid(cipherword, candidate, letter_mapping):
                    valid_candidates.append(candidate)

            # if no valid candidates were found for the current cipherword, then it skips to the next cipherword
            if len(valid_candidates) == 0:

                continue

            # this mapping will get all the possible plaintext letters for each ciphertext letter based on the valid candidates found for the current cipherword
            # Ex: {"A": [], "B": [], etc...} --> the rest of the lists for each letter are also empty 
            candidate_mapping = ssh.getBlankCipherletterMapping() 


            for candidate in valid_candidates:

                ssh.addLettersToMapping(candidate_mapping, cipherword, candidate) 

            for ciphertext_letter in cipherword:

                allowed_letters = candidate_mapping[ciphertext_letter] # gets all the possible plaintext letters for the current ciphertext letter 
                current_letters = letter_mapping[ciphertext_letter] # gets the possible plaintext letters already in the main mapping

                # if the current has no known possible letters, then it just copiess the allowed letters from the candidate mapping into the main mapping
                if len(current_letters) == 0:
                    letter_mapping[ciphertext_letter] = allowed_letters.copy()

                # if it actually has possible letters, then it checks if any of the current letters are not in the allowed letters from the candidate mapping and removes them from the main mapping
                else:
                    remaining_letters = [] # this will hold the letters that should be kept 

                    for plaintext_letter in current_letters:

                        # if the current letter is in the allowed letters from the candidate mapping, then it adds it to the remaining_letters list
                        if plaintext_letter in allowed_letters:
                            remaining_letters.append(plaintext_letter)

                    letter_mapping[ciphertext_letter] = remaining_letters # stores the updated list of possible letters for the current ciphertext letter in the main mapping

            letter_mapping = ssh.removeSolvedLettersFromMapping(letter_mapping)  # removes already-solved plaintext letters from other unsolved letters' possible lists

        # checks if the letter mapping has changed after the current iteration, if not it raises an error because it means that the decryption is stuck and can't make any more progress
        if letter_mapping == previous_mapping:

            raise ValueError("Stopped before decryption was complete.")

def test():

    # Provided test.
    message = 'Sy l nlx sr pyyacao l ylwj eiswi upar lulsxrj isr sxrjsxwjr, ia esmm rwctjsxsza sj wmpramh, lxo txmarr jia aqsoaxwa sr pqaceiamnsxu, ia esmm caytra jp famsaqa sj. Sy, px jia pjiac ilxo, ia sr pyyacao rpnajisxu eiswi lyypcor l calrpx ypc lwjsxu sx lwwpcolxwa jp isr sxrjsxwjr, ia esmm lwwabj sj aqax px jia rmsuijarj aqsoaxwa. Jia pcsusx py nhjir sr agbmlsxao sx jisr elh. -Facjclxo Ctrramm'
    assert(hackSimpleSub(message)=="If a man is offered a fact which goes against his instincts, he will scrutinize it closely, and unless the evidence is overwhelming, he will refuse to believe it. If, on the other hand, he is offered something which affords a reason for acting in accordance to his instincts, he will accept it even on the slightest evidence. The origin of myths is explained in this way. -Bertrand Russell")
    # End of provided test.
    

if __name__ == '__main__':
    test()
