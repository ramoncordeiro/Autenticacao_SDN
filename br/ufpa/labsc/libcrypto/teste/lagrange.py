#importar o p aqui ou seria o q ?

from sympy import Symbol
from sympy.abc import x
import mpmath
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgFunc import ElGamalSgFunc
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgKeyPairGen import ElGamalSgKeyPairGen
from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
import json

jsonPK = ''
with open('/home/ramon/minhaschaves/MinhaChavePublica.json', 'r') as content_file:
    jsonPK = content_file.read()

# decode PK json
codDec = CodDecJson()
pk = codDec.deserialize(jsonPK, ElGamalSgPK)

#q = pk.getPrimoQ()
#print ("Valor de q", q)


def inversor(x,q):
    a = pow(x,q-2,q)
    return a
'''
def verificaInt(x):
    verif = (x).is_integer()
    return verif
'''

def lagrange(x0,x1,x2,q):
    x = Symbol('x')

    l0n = x1 * x2
    l0d = (x0 - x1) * (x0 - x2)
    #print ("denominador L0D antes inverso: ",l0d)
    l0d = (inversor(l0d, q))
    #print ("Inverso Lo D: ", l0d)
    #a = l0n / l0d

    l1n = x0*x2
    l1d = (x1-x0)*(x1-x2)
    #print ("denominador L1D antes inverso: ", l1d)
    l1d = (inversor(l1d, q))
    #print ("Inverso L1 D: ", l1d)
    #b = l1n/l1d

    l2n = x0 * x1
    l2d = (x2 - x0) * (x2 - x1)
    #print ("denominador L2D antes inverso: ", l2d)
    l2d = (inversor(l2d, q))
    #print ("Inverso L2 D: ", l2d)
    #c = l2n/l2d

    #if(verificaInt(float(a))==False):

    l0 = (l0n*l0d)
    #else:
    #    l0 = l0n/l0d

    #if (verificaInt(float(b)) == False):

    l1 = (l1n * l1d)
    #else:
    #    l1 = l1n / l1d

    #if (verificaInt(float(c)) == False):

    l2 = (l2n * l2d)
    #else:
    #    l2 = l2n / l2d

    l0 = (l0%q)
    l1 = (l1 % q)
    l2 = (l2 % q)

    #print("Lagrange 0 :",l0 )
    #print("Lagrange 1 :", l1)
    #print("Lagrange 2 :", l2)

    lagranges = []
    lagranges.append(l0)
    lagranges.append(l1)
    lagranges.append(l2)

    return lagranges
#'''
a = lagrange(2,4,5,22)

for x in a:
    print ("lagrange dentro da funcao de: ", x)

#'''