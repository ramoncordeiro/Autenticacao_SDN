

__author__ = 'leonardo'

from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalWrappler import ElGamalWrappler

'''
Esta classe codifica/decodifica uma cifra ElGamal.

Autor: Leonardo da Costa
Versao: 0.1 - 01/06/2015
'''

class CodDecEGCifra(ElGamalWrappler):

    def __init__(self, EGAlfa = None, EGBeta = None):
        '''
        Construtor da classe

        :param EGAlpha: parametro alfa da cifra ElGamal
        :param EGBeta: parametro beta da cifra ElGamal
        '''

        self.EGAlfa = EGAlfa
        self.EGBeta = EGBeta

        # parametro secreto 'r' da cifra ElGamal
        self.secParamR = None

    '''
    Getters and setters
    '''
    def getEGAlfa(self):
        return self.EGAlfa

    def setEGAlfa(self, EGAlfa):
        self.EGAlfa = EGAlfa

    def getEGBeta(self):
        return self.EGBeta

    def setEGBeta(self, EGBeta):
        self.EGBeta = EGBeta

    def getSecParamR(self):
        return self.secParamR

    def setSecParamR(self, secParamR):
        self.secParamR = secParamR