'''
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
'''

# OLHAR A FUNCAO SOCKET TCP. TA QUASE TUDO PRONTO. 
# FALTA TALVEZ FAZER OS IMPORTS CORRETOS. OLHAR O TESTE2.PY DO PYCHARM

import socket
import sys
import netifaces

sys.path.append('Autenticacao/br/ufpa/labsc')
sys.path.append('Autenticacao')
#from ryu.app.CodDecJson import CodDecJson

from libcrypto.teste import * #esse import ta funcionando pq a pasta tem o mesmo nome do arquivo
from libcrypto.nizkp import *
from libcrypto.misc import *
from libcrypto.randnumgen import *
from libcrypto.cryptosys import *

#import lagrange
from sympy import Symbol
from sympy.abc import x
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
import json
import cPickle
import base64


#import shamir
import random
from br.ufpa.labsc.libcrypto.teste.autenticador import Autenticador
from br.ufpa.labsc.libcrypto.randnumgen.RandNumGen import RandNumGen



class Autenticador():
    #self.a1=41613422514743278755185104612809188927666242200758156012605599128856302132675887938858663777505347710904709669539791760760413227214009760645174026412010174915595764999795527231548884066370742548061664760683971229819230908139183015612368677221293531881206409758428778409963475274064410294186788843271692683613
    
    
    p = None
    q = None
    s = None
    ip = 0
    hosts = {1: '10.0.0.2', 2 : '10.0.0.3', 3 : '10.0.0.4', 4 : '10.0.0.5', 5 : '10.0.0.6'}
    index = 0
    a1=41613422514743278755185104612809188927666242200758156012605599128856302132675887938858663777505347710904709669539791760760413227214009760645174026412010174915595764999795527231548884066370742548061664760683971229819230908139183015612368677221293531881206409758428778409963475274064410294186788843271692683613
    a2=102495741530710854013613913035704420120924232847464836067403778846838618360382922243465198469315673568242788247135233747771771457776656658832546738602933412624439766191679777984942953103909878077304475679934601687661880061734768500640449622097358759529690114781543711399165149471214495550355621139112883358676
    
    '''
    def __init__():
        print "classe iniciada"
    '''
    #removi secret do construtor porque e um parametro que sera calculado
    def __init__(self, **kwargs):
        self.id = none
        print self.id
        self_secret = None
        self.p = 0
        self.q = 0
        self.s = 0
        self.ip = '10.0.0.2'
        self.hosts = {1: '10.0.0.2', 2 : '10.0.0.3', 3 : '10.0.0.4', 4 : '10.0.0.5', 5 : '10.0.0.6'}
        self.index = 0
        self.a1=41613422514743278755185104612809188927666242200758156012605599128856302132675887938858663777505347710904709669539791760760413227214009760645174026412010174915595764999795527231548884066370742548061664760683971229819230908139183015612368677221293531881206409758428778409963475274064410294186788843271692683613
        self.a2=102495741530710854013613913035704420120924232847464836067403778846838618360382922243465198469315673568242788247135233747771771457776656658832546738602933412624439766191679777984942953103909878077304475679934601687661880061734768500640449622097358759529690114781543711399165149471214495550355621139112883358676

    def setId(self,id):
        self.id = id

    def getId(self):
        return self.id

    def setSecret(self,secret):
        (self.secret) = long(secret)

    def getSecret(id):
        if(id==2):
            arq = open('minhaschaves/sham_a2.txt','r')
            #arq = open('minhaschaves/sham_a1.txt','r')
            sec = arq.readline()
            sec = long(sec)
            #print "arq.read print: ", arq.read()
            arq.close()
        if(id==3):
            arq = open('minhaschaves/sham_a3.txt','r')
            #arq = open('minhaschaves/sham_a2.txt','r')
            sec = arq.readline()
            sec = long(sec)
            arq.close()
        if(id==4):
            arq = open('minhaschaves/sham_a4.txt','r')
            #arq = open('minhaschaves/sham_a3.txt','r')
            sec = arq.readline()
            sec = long(sec)
            arq.close()
        if(id==5):
            arq = open('minhaschaves/sham_a5.txt','r')
            #arq = open('minhaschaves/sham_a4.txt','r')
            sec = arq.readline()
            sec = long(sec)
            arq.close()
        if(id==6):
            arq = open('minhaschaves/sham_a6.txt','r')
            #arq = open('minhaschaves/sham_a5.txt','r')
            sec = arq.readline()
            sec = long(sec)
            print "segredo de shamir: ", id, ": ", sec
            arq.close()
        #return self.secret
        #print "segredo dentro funcao getSecret: ",sec
        #print "Tipo do sec, getSecret: ",type(sec)
        return sec
    def recomputarSegredo(self,l):
        val = self.secret*l
        return val
    
    def recomputarMensagem(b,p,id,getSecret):
        #c,p,id_,getSecret ##chamada no socket
        ####recomputarMensagem(aut[1].getsecret(),c.getEGAlfa(),p)
        #if (id==1):
        #secret = getSecret(id)
        sec = getSecret(id)
        print "Secret shamir: ", id, " :",sec
        #print "secret dentro da recomputarMensagem: ",sec
        #print ("segredo autenticador: ",self.getsecret())
        #print ("B dentro da funcao: ", b)
        #print ("p dentro da funcao: ", p)
        mensagem = pow(b,sec,p) #%p
        #print ("trecho mensagem computado autenticador: ", mensagem)
        return mensagem
    
    #essa funcao tera apenas no primeiro autenticador, ele enviara para os outros 
    def calc_a0a1():
        randnumgem = RandNumGen()
        #a = []
        a1 = random.getrandbits(1024)
        a2 = random.getrandbits(1024)    
        arq = open('minhaschaves/a1.txt', 'w')
        arq.write(str(a1))
        arq.close()
        arq2 = open('minhaschaves/a2.txt', 'w')
        arq2.write(str(a2))
        arq2.close()
        #a.add(a1)
        #a.add(a2)

        #return a 
    def shamir(id,get_p_q):
        a = get_p_q()
        #print "p: ", p
        p = a[0]
        #print "type p: ", type(p)
        q = a[1]
        #print "type q: ", type(q)
        s = a[2]
        arq = open('minhaschaves/a1.txt', 'r')
        a1 = arq.readline()
        a1 = long(a1)
        arq2 = open('minhaschaves/a2.txt', 'r')
        a2 = arq2.readline()
        a2 = long(a2)
        #print "s no shamir: ", s
        #print "type s: ", type(s)
        #print "s :", s[0]
        #print "s2 :",s[1]
        #print "s3: ", s[2]
        #print "print p: ", a[0]           
        sec = ((a2*pow(id,2)) + a1*id + s)%q           #p1+p2+p3
        #nome = "sham_a"+str(id)
        if(id==2):
            arq = open('minhaschaves/sham_a2.txt', 'w')
            arq.write(str(sec))
            arq.close()
        if(id==3):
            arq = open('minhaschaves/sham_a3.txt', 'w')
            arq.write(str(sec))
            arq.close()
        if(id==4):
            arq = open('minhaschaves/sham_a4.txt', 'w')
            arq.write(str(sec))
            arq.close()
        
        if(id==5):
            arq = open('minhaschaves/sham_a5.txt', 'w')
            arq.write(str(sec))
            arq.close()
        if(id==6):
            arq = open('minhaschaves/sham_a6.txt', 'w')
            arq.write(str(sec))
            arq.close()
        '''
        #if(aut.getId()>3):
        #    sec = ((a2*(pow(aut.getId(),2)))+ a1*aut.getId()+s)%q
        

        #self.setSecret(sec)
        
        print "segredo de shamir: ",sec

        #aut.secret = sec
        #print "segredo ",self.getSecret()
        return sec   #self.getSecret()

        '''
    def inversor(x,q):
        a = pow(x,q-2,q)
        return a

    #aqui a funcao ta diferente do pycharm. Cada um calcula seu lagrange pegando apenas o Id do outro.
    def lagrange(vet, index, inversor,q): #indexes[array], id, inversor,q
        #x1 = input("insira x1 do lagrange: ")
        #x2 = input ("insira x2 do lagrange: ")
        #x = Symbol('x')
        
        print "vetor antes de ordenar: ", vet
        vetr = sorted(vet,key=int)
        print "vetor de indices ordenado: ", vetr
        #vetr2 = vet.sort(key=int)
        #print "vetor de indices ordenado outra forma: ", vetr2
        
        #self.get_index()
        x0 = vetr[0]
        x1 = vetr[1]
        x2 = vetr[2]
        if(index==vetr[0]):
            l0n = x1 * x2
            l0d = (x0 - x1) * (x0 - x2)
            #print ("denominador L0D antes inverso: ",l0d)
            l0d = inversor(l0d, q)
            #print ("denominador L0D pos inverso: ",l0d)
            l0 = (l0n*l0d)
            l0 = (l0%q)
            print "retorno da funcao lagrange, Lo: ", l0
            return l0
        if(index==vetr[1]):
            l1n = x0*x2
            l1d = (x1-x0)*(x1-x2)
            l1d = inversor(l1d, q)
            l1 = (l1n * l1d)
            l1 = (l1 % q)
            print "retorno da funcao lagrange, L1: ", l1
            return l1
    
            
            #print("Lagrange 0 :",l0 )
            #print("Lagrange 1 :", l1)
            #print("Lagrange 2 :", l2)
           

        if(index==vetr[2]):
            l2n = x0 * x1
            l2d = (x2 - x0) * (x2 - x1)
            l2d = inversor(l2d, q)
            l2 = (l2n * l2d)
            l2 = (l2 % q)
            print "retorno da funcao lagrange, L2: ", l2
            return l2
    
    #Normalmente Ip e 10.0.0.x (sendo x 1,2,3..)
    #porta por ser 6633
    
    #aqui tem q ser passado o parametro ip e porta. Esta sem so pra teste        
    
    #nessa funcao tem q ajeitar a questao do IP e MAC pra pegar o IP e MAC do host criado no mininet
    '''
    def get_index(self):
        for i in self.hosts:
            if (self.hosts[i]==self.ip): 
                self.index = i
    '''            
    
    
    
    
    
    '''
    def get_ip_other(ind):
        for i in self.hosts:
            if self.i==ind
    '''
    



    '''
    
    def create_tcp_packet(data, dst_mac, dst_ip, dst_port):
        e = ethernet.ethernet(dst=dst_mac, src='08:60:6e:7f:74:e7', ethertype=ether_types.ETH_TYPE_IP)      
        ip = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=0, identification=0, flags=0, ttl=255, proto=0, csum=0, src='127.0.0.1', dst="127.0.0.1", option=None)
        tcp_prot = tcp.tcp(src_port=5000, dst_port=dst_port, seq=0, ack=0, offset=0,bits=0, window_size=0, csum=0, urgent=0, option=None)
        tcp_prot.has_flags(tcp.TCP_SYN)          
        p = packet.Packet(data)
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(tcp_prot)
        print "pacote tcp ", repr(p.data)
         
        return p
    
    #rever essa funcao aqui.
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        pkt = ev
        e = pkt.get_protocol(ethernet.ethernet)
        
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        #return pkt_tcp.data
        return pkt.data
    '''    
    def get_p_q():
        jsonPK = ''
        with open('/home/ramon/minhaschaves/MinhaChavePublica.json', 'r') as content_file:
            jsonPK = content_file.read()

        # decode PK json
        codDec = CodDecJson()
        pk = codDec.deserialize(jsonPK, ElGamalSgPK)


        jsonSK = ''
        with open('/home/ramon/minhaschaves/MinhaChavePrivada.json', 'r') as content_file:
            jsonSK = content_file.read()

        sk = codDec.deserialize(jsonSK, ElGamalSgSK)
        #m = 26175871273491982894984981280409
        primos = []
        p = pk.getPrimoP()
        q = pk.getPrimoQ()
        s = sk.getPrivKey()
        #print "S dentro da funcao p_q : ",s
        primos.append(p)
        primos.append(q)
        primos.append(s)
        #m = 44456
        #print ("m a ser cifrado = ",  str(m))
        #print

        #func = ElGamalSgFunc(pk, sk)
        #c = func.EGCifrar(m)
        #cj = cPickle.dumps(c)
        #ALEM DA DECODIFICACAO DO PACOTE, TEM QUE FAZER A DECODIFICACAO DO DADO PRA MOSTRAR O DADO ACIMA
        return primos
    
    
    # autenticador que envia o a0 e o a1 para os outros autenticadores    
    def cliente_socket_a0a1(self, ip, calc_a0a1):
        host = ip #pode ser que mude esse ip
        port = 5000
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest = (host,port)
        tcp.connect(dest)
        print('conectado com autenticador: ', ip)
        #tcp.sendto(msgpack.dump(a),(host,port))
        #PRECISO CONVERTER O PACOTE EM BUFFER PARA PODER ENVIAR VIA SOCKET
        #dado = buffer(a)
        #print (dado)
        #a.encode('utf-8')
        #b = json.dumps(a.__dict__)
        #print ("objeto em Json: ", a)
        
        #tcp.sendall(a)
        ao_a1 = calc_a0a1
        ao_a1 = cPickle.dumps(ao_a1)
        tcp.sendall(ao_a1)
        
        


    def server_socket_TCP(self, ip, lagrange, shamir, get_p_q, a1, a2):
        host = ip
        port = 5000 #posso mudar essa porta.
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        orig = (host, port)
        tcp.bind(orig)
        tcp.listen(1)
        print ("Servidor levantado com sucesso ---- AGUARDANDO CONEXAO DO CONTROLADOR ")
        while True:
            conexao, cliente = tcp.accept()
            print 'Conectador por', cliente
            data = conexao.recv(4096)
            #print ('Recebido ', repr(data))
                       
            data = cPickle.loads(data)
            #b e o valor da funcao de decriptar. No slide e o b elevado ao segredo do autenticador
            
            #b = da.getEGAlfa()
            #aswer = None 
            
            # --------------------------- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ----------------------
            #verificar direito esse tratamento do pacote aqui. Pode dar errado.
            
            answer = self._packet_in_handler(data)
            print ("pacote antes de encode base64 ", answer)
            
            #answer = cPickle.dumps(answer)
            #answer = cPickle.dumps(answer)
            
            answer = base64.urlsafe_b64encode(cPickle.dumps(answer))
            print ("dado enviado pelo usuario sem Json, criptografia, nada:  ", answer)
            
            
            primos = get_p_q()
            p = primos[0]
            q = primos[1]
            s = primos[2]
            b = answer.getEGAlfa()
            lag = self.lagrange()
            #a0 = a[0]
            #a1 = a[1]
            sham = self.shamir(s,q,a1,a2)
            #rec_mensa = recomputarMensagem()
            
            #falta inserir no codigo o c, p e q
            rec_mensagem = self.recomputarMensagem(self.getSecret(), b, p)
            #inserir funcao de calcular mensagem
            dados = []
            dados.add(rec_mensagem)
            dados.add(lag)
            dados = cPickle.dumps(dados)
            #conexao.sendall(dados)

    def server_receive_a0a1(ip):
        host = '0.0.0.0'
        port = 5000 #posso mudar essa porta.
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        orig = (host, port)
        tcp.bind(orig)
        tcp.listen(1)
        print ("Servidor levantado com sucesso ")
        while True:
            conexao, cliente = tcp.accept()
            print 'Conectador por', cliente
            data = conexao.recv(4096)
            print ('Recebido COEFICIENTE PARA SHAMIR ---------')#, repr(data))
            print data           
            #da = cPickle.loads(data)
            #print ("Dado recebido: ", da)
            #print ("A0 e: ",da)
            #print ("A0 e: ",da[1])
            
            #da = base64.urlsafe_b64decode(da)
            #da = cPickle.loads(da)
            #aswer = None 
            
            #answer = cPickle.dumps(answer)
            #answer = cPickle.dumps(answer)
            
        #return da

    def server_socket_Controller(ip,id_,get_p_q,recomputarMensagem,getSecret, lagrange, inversor,get_index_aut,get_cifra):
        host = ip
        print "IP do servidor: ", host
        port = 5000 #posso mudar essa porta.
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        orig = (host, port)
        tcp.bind(orig)
        tcp.listen(5)
        print ("Servidor levantado com sucesso ")
        while True:
            conexao, cliente = tcp.accept()
            print 'Conectador por', cliente
            data = conexao.recv(4096)
            print ('PET ---------')#, repr(data))
            print data
            #print "data[0]: ", data[0]
            #print "data[1]: ", data[1]
            #print "data[2]: ", data[2:308]  ##AQUI VERSAO COM POX
            #print "data[3]: ",data[310:320]  ##AQUI VERSAO COM POX

            #print "data 0: ", data[0]
            #dat = zip(*data)[1]
            #print "DATA 1: ",dat
            #print "DADOS RECEBIDOS: ", data
            #shamir(self.s,self.q,self.a1,self.a2)
            val = get_p_q()
            #print "p_q: ",val
            p = val[0]
            q = val[1]
            #shamir()
            #print "valor de p: ",p
            #b,p,id,getSecret

            #secret = getSecret(id)

            ''' VOU INSERIR UM VALOR DE CIFRA AQUI, SO PRA FAZER O TESTE DA FUNCAO '''
            #cifra = 4919318491849158149201548578394184
            #cifra = data[0]
            #cifra = data
            
            
            '''
            m = recomputarMensagem(cifra,p,id_,getSecret)  
            print "Mensagem computada pelo autenticador: ",m         
            m = cPickle.dumps(m)
            print "Tamanho Mensagem enviada pelo autenticador: "
            print "--------------------------------------------------------------------------------"
            print len(m)
            '''
            
            
            
            #ind = []
            #ind = data[1]
            
            ##ind = data.split()
            
            #print "item da lista 1: ", data[0:0]
            #print "item da lista 2: ", data[1:1]
            #print "tamanho da lista: ", len(data)
            
            #print "lista: ",data[310:319]
            #print "CIFRA: ", data[1:308]
            #dat = data.split(",")
            #print "DADOS APOS SPLIT: ",dat
            
            
            c = data[1:613] #USANDO POX
            c = get_cifra(c)
            #c = data[1]
            print "CIFRA:",c
            lista = data[614:626] #USANDO POX
            print lista
            #lista = data[309:315]
            '''
            print "LISTA[0]: ",lista[0]
            print "LISTA[1]: ",lista[1]
            print "LISTA[2]: ",lista[2]
            print "LISTA[3]: ",lista[3]
            print "LISTA[4]: ",lista[4]
            print "LISTA[5]: ",lista[5]
            print "LISTA[6]: ",lista[6]
            print "LISTA[7]: ",lista[7]
            print "LISTA[8]: ",lista[8]
            #print "LISTA[9]: ",lista[9] 
            '''
            indexes = []
            
            '''
            print "cifra na variavel: ", c
            print "Lista na variavel: ", lista
            print "tipo Lista: ", type(lista)
            print "tipo cifra: ", type(c)
            print "tamanho lista: ", len(lista)
            print "tamanho cifra: ", len(c)
            print "primeiro elemento da lista: ", lista[2]
            print "segundo elemento da lista: ", lista[5]
            print "terceiro elemento da lista: ", lista[8]
            '''
            c = long(c)
            print "cifra depois de transformar em Long: ", c
            print "-------------------------------------------------------------------------------------"
            print "novo tipo da cifra: ", type(c)
            
            indexes = get_index_aut(lista)
            #adhwudwa = get_index_aut(lista)
            #print "indices Coletados na funcao:  ",adhwudwa
            #indexes.append(int(lista[2]))
            #indexes.append(int(lista[5]))
            #indexes.append(int(lista[8]))
            
            
            #indexes.append(lista[2])
            #indexes.append(lista[5])
            #indexes.append(lista[8])
            #indexes = get_index_aut(lista)
            print "indices na nova estrtura de dados: ", indexes
            
            '''
            print "indice 1:",indexes[0]
            print "indice 2:",indexes[1]
            print "indice 3:",indexes[2]
            '''
            
            #print "tipo dos indices 1: ", type(indexes[0]) 
            
            
            '''
            print data[300]
            ind0 = ind[0]
            ind1 = ind[1]
            ind2 = ind[2]
            ind2_2 = ind2.split()
            print "indices: ", ind[0]
            print "item do vetor 0: ", ind[0].split()
            print "item do vetor 1: ", ind[1].split()
            print "item do vetor 2: ", ind[2].split()
            print "item do vetor 3: ", ind[3].split()

            print "tipo ind2: ",type(ind2) 
            print "Indices dos autenticadores: ", data[0]
            '''


            
            #print "indices para o Lagrange: ", indices
            lag = lagrange(indexes, id_, inversor,q) #Lagrange, calculo
            #print "Lagrange: ", lag
            
            #da = cPickle.loads(data)
            #print ("Dado recebido: ", da)
            
            #print ("A0 e: ",da)
            #print ("A0 e: ",da[1])
            
            #da = base64.urlsafe_b64decode(da)
            #da = cPickle.loads(da)
            #aswer = None 
            
            #answer = cPickle.dumps(answer)
            #answer = cPickle.dumps(answer)
            m = recomputarMensagem(c,p,id_,getSecret)  
            print "Mensagem computada pelo autenticador: ",m         
            #m = cPickle.dumps(m)
            #print "Tamanho Mensagem enviada pelo autenticador: "
            #print "--------------------------------------------------------------------------------"
            #print len(m)

            data_to_send = []
            data_to_send.append(lag)
            data_to_send.append(m)
            data_to_send = str(data_to_send)
            print "sera enviado para controlador: ", data_to_send
            conexao.send(data_to_send)
            
        #return da    
    def get_index_aut(lista):
        #print "LISTA DENTRO get_index_aut: ", lista
        #print "Lista[0]: ", lista[0]
        #print "Lista[1]: ", lista[1]
        #print "Lista[2]: ", lista[2]
        aut_index=[]
        
        for n in lista:
            try:
                aut_index.append(int(n)) 
            except:
                pass
        '''
        if(int(lista[2])):
            aut_index.append(int(lista[2]))
            aut_index.append(int(lista[5]))
            aut_index.append(int(lista[8]))
        if(int(lista[3])):
            aut_index.append(int(lista[3]))
            aut_index.append(int(lista[6]))
            aut_index.append(int(lista[9]))
        '''
        #print "AUT_INDEX dentro Get_index_aut: ",aut_index    
        return aut_index
    
    def get_cifra(cif):
        cifra = []

        for n in cif:
            try:
                if not int(cif[613]):#cifra.append(int(n))
                    cif = cif[1:612]
            except:
                pass
        
        return cif
    
    
    
    def cliente_socket_controlador():
        host = '10.0.0.110' #pode ser que mude esse ip
        port = 52686
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest = (host,port)
        tcp.connect(dest)
        print('conectado com autenticador: ', host)
        
        while True:
            try:
                
                print ("-------------------- Iniciar troca com controlador -------")
                # AQUI SERA ENVIADO A CREDENCIAL DO USUARIO
                
                msg = "------------------------ AUTENTICADOR ENVIANDO MENSAGEM *************************************"
                
                #print "tamanha da credencial: ", len(msg)
                #print ("-------------------- credencia em json -------- ",cred)
                #cred = cPickle.dumps(cred)
                #print ("credencial sera enviada enviada ----------------------", cred)
                tcp.sendall(msg)
                print tcp.recv(1024)
                response = tcp.recv(2048)
                print "resposta do controlador: ", response
                if not response:
                    break
            except KeyboardInterrupt:
                print "tchau!"
                break
        
        tcp.close()


    


    #TIRAR COMENTARIO SOMENTE QUANDO FOR TESTAR
    #cliente_socket_TCP()
    
    #server_socket_TCP()

    #print('Insira o IP ')
    interf = netifaces.interfaces()[1]
    bloc = netifaces.ifaddresses(interf)[2]
    bloc2 = bloc[0]
    ip = bloc2['addr']
    #server_receive_a0a1(ip)
    #a1 = server_socket_Controller(ip)
    #cliente_socket_controlador()
    d = ip.split('.')
    ide = eval(d[3])
    ide = int(ide)
    print ide
    print "tipo id", type(ide)
    #self.setId(ide)
    #self.setId(ide)
    #shamir(ide, get_p_q,p,q,a1,a2)
    #print "P apos a saida da funcao: ", p
    
    #shamir(ide,get_p_q)
    #calc_a0a1()
    server_socket_Controller(ip,ide,get_p_q,recomputarMensagem,getSecret, lagrange, inversor,get_index_aut,get_cifra) 
    
    #print ("a1 recebido do prim autenticador ", a1)
    #a2 = server_receive_a0a1(ip)
    #print ("a2 recebido do prim autenticador ", a2)
    #server_socket_TCP(ip, lagrange, shamir, a1, a2)
