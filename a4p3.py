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

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def load_dict():

    dictionary_words = []

    with open("dictionary.txt", "r") as file:
        for line in file:

            word = line.strip().upper() 

            # checks if the word is empty and only has uppercase letters, if not it skips the word
            # [A-Z] means that the word can only have those letters (uppercase)
            # the "+" at the end means that there can be one or more of those symbols inside the brackets
            if re.fullmatch("[A-Z]+", word) is None: 

                continue

            dictionary_words.append(word)

    return dictionary_words


def is_word_valid(cipherword, candidate, letter_mapping):

    cipherword = cipherword.upper() # this is the encrypted word that we're checking
    candidate = candidate.upper() # this is a dictionary word that might be its plaintext

    cipher_to_plaintext = {} # this will hold the letter pairs that are already solved during the check --> this dict will not change letter_mappings

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
        # checks if the current ciphertext has already been assigned in the temp dict
        # if the current assignment is different than the one in the temp dict, it rejects the candidate
        if ciphertext_letter in cipher_to_plaintext:
            if cipher_to_plaintext[ciphertext_letter] != plaintext_letter:

                return False


        for current_ciphertext_letter in cipher_to_plaintext:

            existing_plaintext_letter = (cipher_to_plaintext[current_ciphertext_letter]) # gets the plaintext letter assignmented to each key

            # checks if the existing pair already uses the proposed plaintext letter
            # if not, it rejects the candidate because that means that two different cipher letters are mapping to the same plaintext letter
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

    dictionary_words = load_dict()
    letter_mapping = ssh.hackSimpleSub(message)
    cipherwords = re.findall("[A-Z]+", message.upper())
    unique_cipherwords = []

    for cipherword in cipherwords:
        if cipherword not in unique_cipherwords:
            unique_cipherwords.append(cipherword)

    while True:

        decryption_complete = True

        for cipherword in unique_cipherwords:

            for ciphertext_letter in cipherword:

                if len(letter_mapping[ciphertext_letter]) != 1:
                    decryption_complete = False

                    break

            if not decryption_complete:

                break

        if decryption_complete:

            return ssh.decryptWithCipherletterMapping(
                message,
                letter_mapping
            )

        previous_mapping = {}

        for ciphertext_letter in LETTERS:
            previous_mapping[ciphertext_letter] = (
                letter_mapping[ciphertext_letter].copy()
            )

        for cipherword in unique_cipherwords:

            pattern_parts = []
            has_undeciphered_letter = False

            for ciphertext_letter in cipherword:

                possible_letters = letter_mapping[ciphertext_letter]

                if len(possible_letters) == 1:
                    plaintext_letter = possible_letters[0]
                    pattern_parts.append(plaintext_letter)

                elif len(possible_letters) > 1:
                    pattern_parts.append(
                        "[" + "".join(possible_letters) + "]"
                    )
                    has_undeciphered_letter = True

                else:
                    pattern_parts.append("[A-Z]")
                    has_undeciphered_letter = True

            if not has_undeciphered_letter:

                continue

            word_pattern = re.compile("".join(pattern_parts))
            valid_candidates = []

            for candidate in dictionary_words:

                if len(candidate) != len(cipherword):

                    continue

                if word_pattern.fullmatch(candidate) is None:

                    continue

                if is_word_valid(cipherword, candidate, letter_mapping):
                    valid_candidates.append(candidate)

            if len(valid_candidates) == 0:

                continue

            candidate_mapping = ssh.getBlankCipherletterMapping()

            for candidate in valid_candidates:

                ssh.addLettersToMapping(
                    candidate_mapping,
                    cipherword,
                    candidate
                )

            for ciphertext_letter in cipherword:

                allowed_letters = candidate_mapping[ciphertext_letter]
                current_letters = letter_mapping[ciphertext_letter]

                if len(current_letters) == 0:
                    letter_mapping[ciphertext_letter] = (
                        allowed_letters.copy()
                    )

                else:
                    remaining_letters = []

                    for plaintext_letter in current_letters:

                        if plaintext_letter in allowed_letters:
                            remaining_letters.append(plaintext_letter)

                    letter_mapping[ciphertext_letter] = remaining_letters

            letter_mapping = ssh.removeSolvedLettersFromMapping(
                letter_mapping
            )

        if letter_mapping == previous_mapping:

            raise ValueError("Stopped before decryption was complete.")

def test():

    # Provided test.
    message = 'Sy l nlx sr pyyacao l ylwj eiswi upar lulsxrj isr sxrjsxwjr, ia esmm rwctjsxsza sj wmpramh, lxo txmarr jia aqsoaxwa sr pqaceiamnsxu, ia esmm caytra jp famsaqa sj. Sy, px jia pjiac ilxo, ia sr pyyacao rpnajisxu eiswi lyypcor l calrpx ypc lwjsxu sx lwwpcolxwa jp isr sxrjsxwjr, ia esmm lwwabj sj aqax px jia rmsuijarj aqsoaxwa. Jia pcsusx py nhjir sr agbmlsxao sx jisr elh. -Facjclxo Ctrramm'
    assert(hackSimpleSub(message)=="If a man is offered a fact which goes against his instincts, he will scrutinize it closely, and unless the evidence is overwhelming, he will refuse to believe it. If, on the other hand, he is offered something which affords a reason for acting in accordance to his instincts, he will accept it even on the slightest evidence. The origin of myths is explained in this way. -Bertrand Russell")
    # End of provided test.
    

if __name__ == '__main__':
    test()
