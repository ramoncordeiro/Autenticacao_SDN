from br.ufpa.labsc.libcrypto.nizkp.PTEquivTest import PTEquivTest

__author__ = 'leonardo'

from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgFunc import ElGamalSgFunc

# get PK json from file
jsonPK = ''
with open('/home/leonardo/MinhaChavePublica.json', 'r') as content_file:
    jsonPK = content_file.read()

# decode PK json
codDec = CodDecJson()
pk = codDec.deserialize(jsonPK, ElGamalSgPK)


jsonSK = ''
with open('/home/leonardo/MinhaChavePrivada.json', 'r') as content_file:
    jsonSK = content_file.read()

# decode SK json
sk = codDec.deserialize(jsonSK, ElGamalSgSK)


func = ElGamalSgFunc(pk, sk)
c1 = func.EGCifrar(33)
print c1.getEGAlfa()
print c1.getEGBeta()

c2 = func.EGCifrar(33)
print c2.getEGAlfa()
print c2.getEGBeta()

pet = PTEquivTest(sk)
print pet.PET(c1, c2)

#import os
#print os.getcwd()
#print os.path.dirname(os.path.abspath(__file__))