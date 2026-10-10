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
CMPUT 331 Assignment 2 Student Solution
September 2026
Author: Albert Ganut
"""

import math
from typing import List

def decipherMessage(key: List[int], message: str) -> str:

    num_of_cols = len(key) # using the length of the key to determine the number of columns in the grid
    num_of_rows = int(math.ceil(len(message) / num_of_cols)) # finding the number of rows we need by dividing the length of the message by the number of columns and rounding up to the nearest int
    num_of_shaded_boxes = (num_of_cols * num_of_rows) - len(message) # multiplies the number of rows and columns and then subtracts the length of the message to find out how many shaded boxes exist
    plaintext = []

    grid_cols = [""] * num_of_cols # initializes an empty list of strings the size of the key
    pointer = 0 # to keep track of where we are in the message

    for col_num in key: # gooes through each col that's associated with the key

        current_col = col_num - 1 # minus 1 because 0-based indexing (for example, "2" in the key would be column 1 on the grid)

        if current_col >= num_of_cols - num_of_shaded_boxes: # checks if the current column has a shaded box
            col_len = num_of_rows - 1 # if so, that column has one less character than the other columns
        else: # if the current column does not have a shaded box, it has the same number of characters as the other columns
            col_len = num_of_rows 

        grid_cols[current_col] = message[pointer : pointer + col_len] # takes a part of the message from the pointer up to before pointer + col_len and assigns it to the current column in the grid
        pointer += col_len # increments the pointer by the length of the current column

    for row in range(num_of_rows):

        for current_col in range(num_of_cols): 
            
            if row < len(grid_cols[current_col]): # checks if the current row is smaller than the length of the string so that it skips the shaded boxes
                plaintext.append(grid_cols[current_col][row])

    return "".join(plaintext)

def test():
    assert decipherMessage([2, 4, 1, 5, 3], "IS HAUCREERNP F") == "CIPHERS ARE FUN"

from sys import flags

if __name__ == "__main__" and not flags.interactive:
    test()
