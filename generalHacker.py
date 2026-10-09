# Affine and Transposition Cipher Hacker
# http://inventwithpython.com/hacking (BSD Licensed)

import os, sys, util, detectEnglish, cryptomath, caesar, affine, transposition

SILENT_MODE = False

def hack(cipherType, ciphertext):
    if cipherType == 'caesar':
        keyRange = range(caesar.NUM_SYM)
    elif cipherType == 'transposition':
        keyRange = range(1,len(ciphertext))
    elif cipherType == 'affine':
        keyRange = range(len(affine.SYMBOLS) ** 2)
    else:
        print("Unknown cipher type: %s" % cipherType)
        sys.exit()

    print('Hacking...')
    print('(Press Ctrl-C or Ctrl-D to quit at any time.)')

    for key in keyRange:
        if cipherType == 'caesar':
            decrypted = caesar.caesar(key, ciphertext)
        elif cipherType == 'transposition':
            decrypted = transposition.decryptMessage(key, ciphertext)
        elif cipherType == 'affine':
            keyA = affine.getKeyParts(key)[0]
            if cryptomath.gcd(keyA, len(affine.SYMBOLS)) != 1:
                continue
            decrypted = affine.affine(key, ciphertext, 'decrypt')

        if not SILENT_MODE:
            print('Tried Key %s... (%s)' % (key, decrypted[:40]))

        if detectEnglish.isEnglish(decrypted):
            print('\nPossible encryption hack:')
            print('Key %s: %s' % (key, decrypted[:200]))
            print('\nEnter D for done, or press Enter')
            response = input('> ')

            if response.strip().upper().startswith('D'):
                return decrypted
    return None

def main():
    ciphertext = util.getTextFromFile()

    cipherType = 'caesar'
    if len(sys.argv) > 2:
        cipherType = sys.argv[2]

    hackedMessage = hack(cipherType, ciphertext)

    if hackedMessage == None:
        print('Failed to hack encryption.')
    else:
        print(hackedMessage)

if __name__ == '__main__':
    main()
