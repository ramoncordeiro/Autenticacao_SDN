

__author__ = 'ramon'

from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgFunc import ElGamalSgFunc
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgKeyPairGen import ElGamalSgKeyPairGen
from br.ufpa.labsc.libcrypto.teste.autenticador import Autenticador
from br.ufpa.labsc.libcrypto.teste.shamir import shamir
from br.ufpa.labsc.libcrypto.teste.lagrange import lagrange
from br.ufpa.labsc.libcrypto.teste.recoPKControlador import recoverPk
from br.ufpa.labsc.libcrypto.teste.compMessage import computeM
from br.ufpa.labsc.libcrypto.teste.RecMensAutent import recomputarMensagem
from br.ufpa.labsc.libcrypto.randnumgen.RandNumGen import RandNumGen
import sys
#from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
#from ElGamalSgPK import ElGamalSgPK
#from ElGamalSgSK import ElGamalSgSK
#from ElGamalSgFunc import ElGamalSgFunc
#from ElGamalSgKeyPairGen import ElGamalSgKeyPairGen

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
m = 26175871273491982894984981280409
#m = 44456
print ("m a ser cifrado = ",  str(m))
print

func = ElGamalSgFunc(pk, sk)
c = func.EGCifrar(m)
#print (c.getEGAlfa())
#print (c.getEGBeta())

print

q = pk.getPrimoQ()
p = pk.getPrimoP()
#print ("Valor de P: ",p)
#aqui to pegando a chave privada
s = sk.getPrivKey()

#iniciar recupera??o da chave privada
rand = RandNumGen()
aut = shamir(3,5,s,q)

#for x in aut:
#    print (x.getId())

#print ("programa esta indo ate aqui - antes de lagrange")

'''
print ("ID ",aut[1].getId())
print ("ID ",aut[3].getId())
print ("ID ",aut[4].getId())
'''

#x0 = aut[1].getId
#x1 = aut[3].getId
b = lagrange(aut[1].getId(),aut[3].getId(),aut[4].getId(),q)
#print ("lagrange 2: ",b[2])
#print ("programa passou do lagrange")
#aut


#print ("Tamanho ",sys.getsizeof(x))

'''
print ("segredo autenticador ", aut[1].getsecret())
print ("segredo autenticador ", aut[2].getsecret())
print ("segredo autenticador ", aut[4].getsecret())
'''

di = aut[1].recomputarSegredo(b[0])
#print ("Valor mensagem pelo aut: ",di)
dj = aut[3].recomputarSegredo(b[1])
dk = aut[4].recomputarSegredo(b[2])

recPk = recoverPk(di,dj,dk,q)
#recPk = int(recPk)
#s = int(s)
print ("chave privada:  ",s)
#recPk = recPk/2
print ("chave privada recuperada: ",recPk)
#termina recupera??o chave privada distribuida

'''
s = str(s)
recPk = str(recPk)
p = str(p)
q = str(q)
b[0] = str(b[0])
b[1] = str(b[1])
b[2] = str(b[2])


print ("Tamanho Pk: ",len(s))
print ("Tamanho PK RECUPERADA, ",len(recPk))
print ("Tamanho P ",len(p))
print ("Tamanho Q",len(q))
print ("Tamanho Lagrange 0",len(b[0]))
print ("Tamanho Lagrange 1",len(b[1]))
print ("Tamanho Lagrange 2",len(b[2]))
'''

if(recPk==s):
    print ("CHAVES IGUAIS")

#INICIA RECUPERAR MENSAGEM
print ("ANTES DA MENSAGEM trechos partes ")

yi = recomputarMensagem(aut[1].getsecret(),c.getEGAlfa(),p)
yj = recomputarMensagem(aut[3].getsecret(),c.getEGAlfa(),p)
yk = recomputarMensagem(aut[4].getsecret(),c.getEGAlfa(),p)
'''
yi = aut[1].recomputarMensagem(aut[1].getsecret(),c.getEGAlfa(),p)
print ("yi: ",yi)
yj = aut[3].recomputarMensagem(c.getEGAlfa(),p)
yk = aut[4].recomputarMensagem(c.getEGAlfa(),p)
'''

#b = str(c.getEGAlfa())
#segredoAut = str(aut[1].getsecret())
#p = str(p)
#print ("O tamanho de b ", len(b))
#print ("O tamanho de segAutenc ", len(segredoAut))
#print ("O tamanho de p ", len(b))


#yi = Process(target=recomputarMensagem, args=(aut[1].getsecret(),c.getEGAlfa(),p,))


#'''
#k = aut[1].getsecret()

#y = aut[1].recomputarMensagem(aut[1].getsecret(),c.getEGAlfa(),p)
#yi = aut[1].recomputarMensagem(aut[1].getsecret(),c.getEGAlfa(),p)
#yj = aut[3].recomputarMensagem(aut[3].getsecret(),c.getEGAlfa(),p)
#yk = aut[4].recomputarMensagem(aut[4].getsecret(),c.getEGAlfa(),p)

'''
print ("ID autenticaor 2: ", aut[1].id)
print ("ID autenticaor 4: ", aut[3].id)
print ("ID autenticaor 5: ", aut[4].id)
'''


#print ("segredo autenticador 2: ", yi)
#print ("segredo autenticador 4: ", yj)
#print ("segredo autenticador 5: ", yk)

#yk = recomputarMensagem(aut[3].getsecret(),c.getEGAlfa(),p)
#print ("trecho mensagem recuperada pelo autenticador: ",yi)


print ("ANTES DA MENSAGEM recuperada")

mensa = computeM(yi,b[0],yj,b[1],yk,b[2],c.getEGBeta(),p)
print ("mensagem recuperada: ", str(mensa))

#m = str(m)
#mensa = str(mensa)
if(m==mensa):
    print ("Mensagens Iguais")
'''

#mDecifrado = func.EGDecifrar(c)
#print 'm decifrado = ' + str(mDecifrado)




'''

'''
keyPairGen = ElGamalSgKeyPairGen()
pkJson = codDec.serialize(keyPairGen.egkpub)
skJson = codDec.serialize(keyPairGen.egkpriv)

print pkJson
print
print
print skJson
'''