

__author__ = 'leonardo'

from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
from ElGamalSgPK import ElGamalSgPK
from ElGamalSgSK import ElGamalSgSK
from ElGamalSgFunc import ElGamalSgFunc
from ElGamalSgKeyPairGen import ElGamalSgKeyPairGen

# get PK json from file
jsonPK = ''
with open('/home/ramon/minhaschaves/MinhaChavePublica.json', 'r') as content_file:
    jsonPK = content_file.read()

# decode PK json
codDec = CodDecJson()
pk = codDec.deserialize(jsonPK, ElGamalSgPK)


jsonSK = ''
with open('/home/ramon/minhaschaves/MinhaChavePrivada.json', 'r') as content_file:
    jsonSK = content_file.read()

# decode SK json
sk = codDec.deserialize(jsonSK, ElGamalSgSK)

m = 44456
print 'm a ser cifrado = ' + str(m)
print

func = ElGamalSgFunc(pk, sk)
c = func.EGCifrar(m)
print c.getEGAlfa()
print c.getEGBeta()
print

mDecifrado = func.EGDecifrar(c)
print "m decifrado =  + str(mDecifrado)"




'''
keyPairGen = ElGamalSgKeyPairGen()
pkJson = codDec.serialize(keyPairGen.egkpub)
skJson = codDec.serialize(keyPairGen.egkpriv)

print pkJson
print
print
print skJson
'''