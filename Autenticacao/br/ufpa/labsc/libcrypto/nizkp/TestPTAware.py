from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgFunc import ElGamalSgFunc
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
from br.ufpa.labsc.libcrypto.nizkp.PTAware import PTAware
import json

__author__ = 'leonardo'

# get PK json from file
jsonPK = ''
with open('/home/leonardo/MinhaChavePublica.json', 'r') as content_file:
    jsonPK = content_file.read()

# decode PK json
codDec = CodDecJson()
pk = codDec.deserialize(jsonPK, ElGamalSgPK)

m = 44456
print 'm a ser cifrado = ' + str(m)
print

func = ElGamalSgFunc(pk)
c = func.EGCifrar(m)
print c.getEGAlfa()
print c.getEGBeta()
print


pt_aware = PTAware(pk.g, pk.p, pk.q, c.secParamR, c.EGAlfa)
pt_aware_challenge = pt_aware.createChallenge()
json = json.dumps(pt_aware_challenge)
print json
print


print pt_aware.verify(pt_aware_challenge)

