from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK

__author__ = 'leonardo'

'''
Esta classe armazena uma chave privada ElGamal.

Autor: Leonardo da Costa
Versao: 0.1 - 27/05/2015
'''

class ElGamalSgSK(ElGamalSgPK):

    def __init__(self, p = None, q = None, g = None, h = None, xsk = None):
        '''
        Construtor da classe

        :param p: primo p
        :param q: primo q
        :param g: gerador
        :param h: chave publica
        :param xsk: chave privada
        '''

        self.desc = "Chave Privada ElGamal"
        self.p = p
        self.q = q
        self.g = g
        self.h = h
        self.xsk = xsk


    '''
    Getters and setters
    '''
    def getPrivKey(self):
        return self.xsk

    def setPrivKey(self, xsk):
        self.xsk = xsk