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

    words_by_length = {}

    with open("dictionary.txt", "r") as file:
        for line in file:
            
            word = line.strip().upper()

            if re.fullmatch('[A-Z]+', word) is None:

                continue

            word_length = len(word) 

            if word_length not in words_by_length:
                words_by_length[word_length] = []

            words_by_length[word_length].append(word)

    return words_by_length

def is_word_valid(cipherword, candidate, letter_mapping):

    cipherword = cipherword.upper()
    candidate = candidate.upper()

    cipher_to_plaintext = {}

    # Record only mappings that are already solved.
    for cipher_letter in LETTERS:

        possible_letters = letter_mapping[cipher_letter]

        if len(possible_letters) == 1:
            plaintext_letter = possible_letters[0]

            # Different ciphertext letters cannot share
            # the same plaintext letter.
            if plaintext_letter in cipher_to_plaintext.values():
                
                return False

            cipher_to_plaintext[cipher_letter] = plaintext_letter

    # Check each letter pair in the candidate.
    for index in range(len(cipherword)):

        ciphertext_letter = cipherword[index]
        plaintext_letter = candidate[index]

        possible_letters = letter_mapping[ciphertext_letter]

        # Reject letters outside a nonempty possibilities list.
        if len(possible_letters) > 0:
            if plaintext_letter not in possible_letters:

                return False

        # A ciphertext letter must keep the same plaintext letter.
        if ciphertext_letter in cipher_to_plaintext:
            if cipher_to_plaintext[ciphertext_letter] != plaintext_letter:

                return False

        # Check whether another ciphertext letter already
        # uses this plaintext letter.
        for current_ciphertext_letter in cipher_to_plaintext:

            existing_plaintext_letter = (
                cipher_to_plaintext[current_ciphertext_letter]
            )

            if existing_plaintext_letter == plaintext_letter:
                if current_ciphertext_letter != ciphertext_letter:

                    return False

        cipher_to_plaintext[ciphertext_letter] = plaintext_letter

    return True

def hackSimpleSub(message: str):
    """
    Simple substitution cipher hacker.
    First runs the textbook program to get an initial, potentially incomplete decipherment.
    Then uses regular expressions and a dictionary to decipher additional letters.
    """

    word_by_length = load_dict()    
    letter_mapping = ssh.hackSimpleSub(message)
    cipherwords = re.findall('[A-Z]+', message.upper())
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

            return ssh.decryptWithCipherletterMapping(message, letter_mapping)

        previous_mapping = {}

        for ciphertext_letter in LETTERS:
            
            previous_mapping[ciphertext_letter] = letter_mapping[ciphertext_letter].copy()

        for cipherword in unique_cipherwords:

            pattern_parts = []
            has_undeciphered_letter = False

            for ciphertext_letter in cipherword:

                possible_letters = letter_mapping[ciphertext_letter]

                if len(possible_letters) == 1:
                    plaintext_letter = possible_letters[0]
                    pattern_parts.append(plaintext_letter)
                elif len(possible_letters) > 1:
                    pattern_parts.append("[" + "".join(possible_letters) + "]")
                    has_undeciphered_letter = True 
                else:
                    pattern_parts.append("[A-Z]")
                    has_undeciphered_letter = True

            if not has_undeciphered_letter:
                
                continue

            if len(cipherword) not in word_by_length:

                continue
            
            word_pattern = re.compile("".join(pattern_parts))
            valid_candidates = []

            for candidate in word_by_length[len(cipherword)]:

                if word_pattern.fullmatch(candidate) is None:

                    continue

                if is_word_valid(cipherword, candidate, letter_mapping):
                    valid_candidates.append(candidate)

            if len(valid_candidates) == 0:

                continue

            candidate_mapping = ssh.getBlankCipherletterMapping()

            for candidate in valid_candidates:

                ssh.addLettersToMapping(candidate_mapping, cipherword, candidate)

            for ciphertext_letter in cipherword:

                allowed_letters = candidate_mapping[ciphertext_letter]
                current_letters = letter_mapping[ciphertext_letter]

                if len(current_letters) == 0:
                    letter_mapping[ciphertext_letter] = allowed_letters.copy()
                else:
                    remaining_letters = []

                    for plaintext_letter in current_letters:

                        if plaintext_letter in allowed_letters:
                            remaining_letters.append(plaintext_letter)

                    letter_mapping[ciphertext_letter] = remaining_letters

            letter_mapping = ssh.removeSolvedLettersFromMapping(letter_mapping)

        if letter_mapping == previous_mapping:
            raise ValueError("Stopped before decryption was complete.")

def test():

    # Provided test.
    message = 'Sy l nlx sr pyyacao l ylwj eiswi upar lulsxrj isr sxrjsxwjr, ia esmm rwctjsxsza sj wmpramh, lxo txmarr jia aqsoaxwa sr pqaceiamnsxu, ia esmm caytra jp famsaqa sj. Sy, px jia pjiac ilxo, ia sr pyyacao rpnajisxu eiswi lyypcor l calrpx ypc lwjsxu sx lwwpcolxwa jp isr sxrjsxwjr, ia esmm lwwabj sj aqax px jia rmsuijarj aqsoaxwa. Jia pcsusx py nhjir sr agbmlsxao sx jisr elh. -Facjclxo Ctrramm'
    assert(hackSimpleSub(message)=="If a man is offered a fact which goes against his instincts, he will scrutinize it closely, and unless the evidence is overwhelming, he will refuse to believe it. If, on the other hand, he is offered something which affords a reason for acting in accordance to his instincts, he will accept it even on the slightest evidence. The origin of myths is explained in this way. -Bertrand Russell")
    # End of provided test.
    

if __name__ == '__main__':
    test()
