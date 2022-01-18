__author__ = 'leonardo'


from br.ufpa.labsc.libcrypto.randnumgen.randpool import RandomPool
from br.ufpa.labsc.libcrypto.randnumgen.number import *


'''
This class uses the files randpool.py and number.py to create a strongly secure random number generator.

Author: Leonardo da Costa
Version: 0.1 - 07/2016

'''
class RandNumGen:

    def genRandomNumber(self, n):
        """
        Generate a random number of n bits.

        :param n: number of bits
        :return: random number of n bits
        """

        number_of_bytes = n/8

        randpool = RandomPool()
        random_bytes = randpool.get_bytes(number_of_bytes)

        random_number = bytes_to_long(random_bytes)

        return random_number