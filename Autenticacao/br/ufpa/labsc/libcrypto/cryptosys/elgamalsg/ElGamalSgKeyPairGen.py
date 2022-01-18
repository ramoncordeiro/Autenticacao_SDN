from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.randnumgen.RandNumGen import RandNumGen

__author__ = 'leonardo'

import random
import sys

'''
Esta classe gera um par de chaves ElGamal no subgrupo Zq/Zp.

Autor: Leonardo da Costa
Versao: 0.1 - 27/05/2015
'''

class ElGamalSgKeyPairGen:

    p = None
    q = None
    g = None
    h = None
    xsk = None

    egkpub = ElGamalSgPK()
    egkpriv = ElGamalSgSK()

    # Probabilidade de um numero gerado ser primo na geracao de numeros primos aleatorios
    #
    prob = 80

    # tamanho da chave em bits - numero primo 'p'
    #
    tamChave = 1024

    def __init__(self):
        '''
        Construtor da classe
        '''

        self.randNumGen = RandNumGen()

        self.selectPrimos()
        # Comment line above and uncomment the two lines below for testing faster
        #self.q = 41285776641819137158467154059138109974365265014376016632582800261266132314959324966207473374464222489872810661363665464787086374662947125019466481506192159643845013019637559157641795358496583191964449981370437313945080220558201942065454569464193146643777680782481837899520246524258861537603038121393966486939
        #self.p = 82571553283638274316934308118276219948730530028752033265165600522532264629918649932414946748928444979745621322727330929574172749325894250038932963012384319287690026039275118315283590716993166383928899962740874627890160441116403884130909138928386293287555361564963675799040493048517723075206076242787932973879
        self.keyPairGen()

        self.egkpub = ElGamalSgPK(self.p, self.q, self.g, self.h)
        self.egkpriv = ElGamalSgSK(self.p, self.q, self.g, self.h, self.xsk)

    def selectPrimos(self):
        i = 1
        print "Trying for the " + str(i) + " time ..."
        i += 1

        # seleciona numero inteiro aleatorio de tamanho tamChave (em bits)
        #self.q = random.getrandbits(self.tamChave - 1)
        self.q = self.randNumGen.genRandomNumber(self.tamChave - 1)

        while self.is_probable_prime(self.q) == False:
            # seleciona numero inteiro aleatorio de tamanho tamChave (em bits) novamente
            #self.q = random.getrandbits(self.tamChave - 1)
            self.q = self.randNumGen.genRandomNumber(self.tamChave - 1)

        self.p = (self.q * 2) + 1

        # enquanto p nao e' primo
        while self.is_probable_prime(self.p) == False:
            print "Trying for the " + str(i) + " time ..."
            i += 1

            # seleciona numero inteiro aleatorio de tamanho tamChave (em bits)
            #self.q = random.getrandbits(self.tamChave - 1)
            self.q = self.randNumGen.genRandomNumber(self.tamChave - 1)

            while self.is_probable_prime(self.q) == False:
                # seleciona numero inteiro aleatorio de tamanho tamChave (em bits) novamente
                #self.q = random.getrandbits(self.tamChave - 1)
                self.q = self.randNumGen.genRandomNumber(self.tamChave - 1)

            self.p = (self.q * 2) + 1

        print "q: " + str(self.q)
        print "p: " + str(self.p)

    def keyPairGen(self):
        self.selectGerador()

        #self.xsk = random.getrandbits(self.tamChave)
        self.xsk = self.randNumGen.genRandomNumber(self.tamChave)
        while self.xsk >= self.q - 1:
            #self.xsk = random.getrandbits(self.tamChave)
            self.xsk = self.randNumGen.genRandomNumber(self.tamChave)

        self.h = pow(self.g, self.xsk, self.p)

    def selectGerador(self):

        #gtmp = random.getrandbits(self.tamChave - 2)
        gtmp = self.randNumGen.genRandomNumber(self.tamChave - 2)
        self.g = pow(gtmp, 2) % self.p

        while (self.g == 0 | self.g == 1 | self.g == self.p - 1):
            #gtmp = random.getrandbits(self.tamChave - 2)
            gtmp = self.randNumGen.genRandomNumber(self.tamChave - 2)
            self.g = pow(gtmp, 2) % self.p

    def is_probable_prime(self, n, k = 7):
       """use Rabin-Miller algorithm to return True (n is probably prime)
          or False (n is definitely composite)"""
       if n < 6:  # assuming n >= 0 in all cases... shortcut small cases here
          return [False, False, True, True, False, True][n]
       elif n & 1 == 0:  # should be faster than n % 2
          return False
       else:
          s, d = 0, n - 1
          while d & 1 == 0:
             s, d = s + 1, d >> 1
          # Use random.randint(2, n-2) for very large numbers
          for a in random.sample(xrange(2, min(n - 2, sys.maxint)), min(n - 4, k)):
             x = pow(a, d, n)
             if x != 1 and x + 1 != n:
                for r in xrange(1, s):
                   x = pow(x, 2, n)
                   if x == 1:
                      return False  # composite for sure
                   elif x == n - 1:
                      a = 0  # so we know loop didn't continue to end
                      break  # could be strong liar, try another a
                if a:
                   return False  # composite if we reached end of this loop
          return True  # probably prime if reached end of outer loop


    '''
    Getters and setters
    '''
    def getPubKey(self):
        return self.egkpub

    def getPrivKey(self):
        return self.egkpriv

    def getGerador(self):
        return self.g