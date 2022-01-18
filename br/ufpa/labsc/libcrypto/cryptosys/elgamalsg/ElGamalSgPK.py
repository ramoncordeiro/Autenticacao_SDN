
__author__ = 'leonardo'

from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalKeyWrappler import ElGamalKeyWrappler

'''
Esta classe armazena uma chave publica ElGamal.

Autor: Leonardo da Costa
Versao: 0.1 - 27/05/2015
'''

class ElGamalSgPK(ElGamalKeyWrappler):

    def __init__(self, p = None, q = None, g = None, h = None):
        '''
        Construtor da classe

        :param p: primo p
        :param q: primo q
        :param g: gerador
        :param h: chave publica
        '''

        self.desc = "Chave Publica ElGamal"
        self.p = p
        self.q = q
        self.g = g
        self.h = h

    def hasH(self):
        '''
        Verifica se a chave possui o parametro h ou nao
        '''

        if self.h == None:
            return False
        else:
            return True


    '''
    Getters and setters
    '''

    def getPrimoP(self):
        return self.p

    def setPrimoP(self, p):
        self.p = p

    def getPrimoQ(self):
        return self.q

    def setPrimoQ(self, q):
        self.q = q

    def getGerador(self):
        return self.g

    def setGerador(self, g):
        self.g = g

    def getH(self):
        return self.h

    def setH(self, h):
        self.h = h

# Uncomment the lines below to test the class
#pk = ElGamalSgPK(2, 3, 4, 5)
#print pk._h()