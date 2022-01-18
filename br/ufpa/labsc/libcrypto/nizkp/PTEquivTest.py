from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.CodDecEGCifra import CodDecEGCifra
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgFunc import ElGamalSgFunc

__author__ = 'leonardo'


class PTEquivTest():

    def __init__(self, sk):
        self.sk = sk

    def PET(self, c1, c2):
        c = CodDecEGCifra()

        alfa = c1.getEGAlfa() * pow(c2.getEGAlfa(), self.sk.p - 2, self.sk.p)
        beta = c1.getEGBeta() * pow(c2.getEGBeta(), self.sk.p - 2, self.sk.p)

        c.setEGAlfa(alfa)
        c.setEGBeta(beta)

        func = ElGamalSgFunc(sk = self.sk)
        m = func.EGDecifrar(c)
        #print 'm = ' + str(m)

        if str(m) == '1':
            return True
        else:
            return False