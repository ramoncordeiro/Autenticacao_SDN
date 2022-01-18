from br.ufpa.labsc.libcrypto.randnumgen.RandNumGen import RandNumGen

__author__ = 'leonardo'

#import random

from CodDecEGCifra import CodDecEGCifra


'''
Esta classe consiste nas seguintes funcoes:
cifrar, decifrar e recifrar usando o algoritmo
de criptografia ElGamal.

Autor: Leonardo da Costa
Versao: 0.1 - 01/06/2015
'''

class ElGamalSgFunc:

    g = None
    p = None
    q = None
    h = None

    # chave secreta ElGamal
    #
    EGsk = None

    def __init__(self, pk = None, sk = None):
        '''
        Construtor da classe.

        :param pk: chave publica ElGamalSgPK
        :param sk: chave privada ElGamalSgSK
        '''

        self.randNumGen = RandNumGen()

        if pk != None:
            self.g = long(pk.getGerador())
            self.p = long(pk.getPrimoP())
            self.q = long(pk.getPrimoQ())
            self.h = long(pk.getH())

        if sk != None:
            self.g = long(sk.getGerador())
            self.p = long(sk.getPrimoP())
            self.q = long(sk.getPrimoQ())
            self.h = long(sk.getH())

            self.EGsk = long(sk.getPrivKey())

    def EGCifrar(self, textoPlano):
        '''
        Cifra um texto plano usando o algoritmo ElGamal.

        :param textoPlano: o texto plano a ser cifrado (long)
        :return: objeto CodDecEGCifra
                 (alfa, beta) = (g^r, messagem*h^r)
        '''

        # seleciona um numero aleatorio pertencente ao grupo Zq
        #
        #rnd = random.getrandbits(self.q.bit_length() - 1)
        rnd = self.randNumGen.genRandomNumber(self.q.bit_length() - 1)

        while rnd >= self.q - 1:
            #rnd = random.getrandbits(self.q.bit_length() - 1)
            rnd = self.randNumGen.genRandomNumber(self.q.bit_length() - 1)

        alfa = pow(self.g, rnd, self.p)
        beta = (textoPlano * pow(self.h, rnd, self.p)) % self.p

        textoCifrado = CodDecEGCifra(alfa, beta)
        textoCifrado.setSecParamR(rnd)

        return textoCifrado

    def EGRecifrar(self, textoCifrado):
        '''
        Recifra um texto cifrado ElGamal.

        :param textoCifrado: texto cifrado ElGamal a ser recifrado (CodDecEGCifra object)
        :return: objeto CodDecEGCifra
        '''

        # seleciona um numero aleatorio pertencente ao grupo Zq
        #
        #print self.q
        #rnd = random.getrandbits(self.q.bit_length() - 1)
        rnd = self.randNumGen.genRandomNumber(self.q.bit_length() - 1)

        while rnd >= self.q - 1:
            #rnd = random.getrandbits(self.q.bit_length() - 1)
            rnd = self.randNumGen.genRandomNumber(self.q.bit_length() - 1)

        # newAlfa = g^r * g^{rnd} (mod p)
        #
        #print type(textoCifrado.getEGAlfa())
        newAlfa = pow(self.g, rnd, self.p)
        newAlfa = (pow(self.g, rnd, self.p) * long(textoCifrado.getEGAlfa())) % self.p

        # newBeta = mh^r * h^{rnd} (mod p)
        #
        newBeta = (pow(self.h, rnd, self.p) * long(textoCifrado.getEGBeta())) % self.p

        novoTextoCifrado = CodDecEGCifra(newAlfa, newBeta)
        novoTextoCifrado.setSecParamR(rnd)

        return novoTextoCifrado

    def EGDecifrar(self, textoCifrado, egSK):
        '''
        Decifra um texto cifrado ElGamal.

        :param textoCifrado: texto cifrado ElGamal a ser decifrado (CodDecEGCifra object)
        :param egSK: chave secreta ElGamal
        :return: inteiro que representa o texto plano obtido
        '''

        egAlfa = textoCifrado.getEGAlfa()
        egBeta = textoCifrado.getEGBeta()

        # (mh^r)/(g^r)^s (mod p)
        # usando modulo inverso dessa forma: modInverse of x mod m = pow(x,m-2,m)
        textoPlano = (egBeta * (pow(pow(egAlfa, egSK, self.p), self.p - 2, self.p))) % self.p

        return textoPlano

    def EGDecifrar(self, textoCifrado):
        '''
        Decifra um texto cifrado ElGamal

        :param textoCifrado: texto cifrado ElGamal a ser decifrado (CodDecEGCifra object)
        :return: inteiro que representa o texto plano obtido
        '''

        egAlfa = textoCifrado.getEGAlfa()
        egBeta = textoCifrado.getEGBeta()

        # (mh^r)/(g^r)^s (mod p)
        # using mod inverse this way: modInverse of x mod m = pow(x,m-2,m)
        textoPlano = (egBeta * (pow(pow(egAlfa, self.EGsk, self.p), self.p - 2, self.p))) % self.p

        return textoPlano

    def Msg2SGroup(self, textoPlano):
        '''
        Codifica uma messagem para o subgrupo Zq/Zp

        :param textoPlano: elemento no grupo Zp
        :return: texto plano codificado para o subgrupo Zq
        '''

        # textoPlano1 + 1
        textoPlano1 = textoPlano + 1

        if (pow(textoPlano1, self.q, self.p) == 1):
            return textoPlano1
        else:
            # novo texto plano = p - textoPlano1
            #
            return self.p - textoPlano1

    def SGroup2Msg(self, textoPlanoCod):
        # textoPlanoCod1 = textoPlanoCod + 1
        textoPlanoCod1 = textoPlanoCod + 1

        if textoPlanoCod <= self.q:
            return textoPlanoCod - 1
        else:
            return self.p - textoPlanoCod - 1