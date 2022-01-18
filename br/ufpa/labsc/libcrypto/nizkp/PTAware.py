
__author__ = 'leonardo'

from br.ufpa.labsc.libcrypto.misc.Hash import Hash
from br.ufpa.labsc.libcrypto.randnumgen.RandNumGen import RandNumGen

class PTAware:

    def __init__(self, g = None, p = None, q = None, r = None, g_r = None):
        self.g = g
        self.p = p
        self.q = q
        self.r = r
        self.g_r = g_r  # ciphertext's alpha param
        self.t = None
        self.I = None
        self.C = None
        self.J = None

    def createChallenge(self):
        hash = Hash()
        C_temp = hash.hashString(str(self.computeI()) + str(self.g_r))
        self.C = long(C_temp, 16)
        self.J = (self.t + self.r * self.C) % self.q
        return {'I': self.I, 'J': self.J, 'C': self.C, 'p': self.p, 'g': self.g, 'alpha': self.g_r}

    def verify(self, C):
        param1 = pow(C['g'], C['J'], C['p'])
        param2 = (C['I'] * pow(C['alpha'], C['C'], C['p'])) % C['p']

        if param1 == param2:
            return True
        else:
            return False

    def computeT(self):
        randNumGen = RandNumGen()
        self.t = randNumGen.genRandomNumber(self.q.bit_length() - 1)
        return self.t

    def computeI(self):
        self.I = pow(self.g, self.computeT(), self.p)
        return self.I

