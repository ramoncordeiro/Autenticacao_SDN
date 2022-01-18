__author__ = 'leonardo'
import hashlib

'''
This class consists of methods used to generate the hash value of a string.

Author: Leonardo da Costa
Version: 0.1 - Aug/20
'''

class Hash():

    def __init__(self):
        '''
        Class constructor
        '''
        pass

    def hashString(self, s):
        '''
        Hashes a string.

        :param s: the string to be hashed
        :return: the hash value of the string s in the hexadecimal form
        '''
        h = hashlib.sha256()
        h.update(s)
        return h.hexdigest()

