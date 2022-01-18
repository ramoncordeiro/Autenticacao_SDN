import random

import random
from br.ufpa.labsc.libcrypto import randnumgen
from br.ufpa.labsc.libcrypto.teste.autenticador import Autenticador
#from br.ufpa.labsc.libcrypto.randnumgen import number
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.randnumgen.RandNumGen import RandNumGen
import sys

def shamir(k,n,s,q):
    tamChave = 1024

    randnumgem = RandNumGen()
    #a1 = random.getrandbits(tamChave-1)
    #a1 = randnumgem.genRandomNumber(q-1)
    #a1 = RandNumGen.genRandomNumber(q-1)

    a1 = random.getrandbits(1024)
    #a1 = 2
    #print ("Valor de a1 ", a1)
    #print ("ai :", a1)
    #a1 = random.randint(1,20)
    #a2 = random.randint(1,20)
    #a2 = 1

    a2 = random.getrandbits(1024)
    #a2 = random.getrandbits(tamChave-1)
    #a2 = randnumgem.genRandomNumber(q-1)

    #a2 = 1
    autent = []
    for x in range(1,6):
        aut = Autenticador(x, None)
        aut.setId(x)
        #print("ID autenticador: ",a.id)

        #p1 = pow(aut.getId(),2)
        #p2 = a1*aut.getId()
        #p3 = s
        #s? d? certo quando o primeiro membro ? multiplicado por 1
        #p1 = a2*pow(aut.getId(),2)
        sec = ((a2*pow(aut.getId(),2)) + a1*aut.getId() + s)%q           #p1+p2+p3
        #if(aut.getId()>3):
        #    sec = ((a2*(pow(aut.getId(),2)))+ a1*aut.getId()+s)%q
        aut.secret = sec
        #a.setSecret = (a.secret)
        #a.secret = s+a2*x+a1*(pow(x,2))
        #print ("segredo ",a.secret)
        autent.append(aut)

    return autent

'''
a = shamir(3,5,6,22)
for x in a:
    print(x.secret)


print ('')
print ("ID autenticadores")
for x in a:
    print (x.getId())
#'''
