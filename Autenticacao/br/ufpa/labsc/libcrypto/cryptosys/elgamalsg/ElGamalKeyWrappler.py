
__author__ = 'leonardo'

from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalWrappler import ElGamalWrappler

'''
Esta classe adiciona metadados as chaves Elgmal.

Autor: Leonardo da Costa
Versao: 0.1 - 27/05/2015
'''

class ElGamalKeyWrappler(ElGamalWrappler):
    authority = None

    def __init__(self):
        pass

    '''
    Getters and setters
    '''
    def getAuthority(self):
        return self.authority

    def setAuthority(self, auth):
        self.authority = auth