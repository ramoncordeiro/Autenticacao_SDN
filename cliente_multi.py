
from ryu.lib.packet import tcp


#from ryu.app import json_teste
import os
import sys
from json_tricks import dumps
#import msgpack
import socket
import cPickle
import base64
import json
import netifaces
import time
#import file

import sys
sys.path.append('ryu/ryu')
from app.CodDecJson import CodDecJson
sys.path.append('Autenticacao')
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgFunc import ElGamalSgFunc
#sys.path.append('Autenticacao/br')

#import PyObject
class Cliente_controller():
    def __init__():
        print "classe cliente criada"

    
    def cliente_socket_controller(encrypt_credentials,save_time):
        #host = '192.168.56.110' #pode ser que mude esse ip
        #host = '192.168.0.22'
        #host = '10.0.0.255'
        #host = '10.0.1.255'
        #host = '0.0.0.0'
        host = '10.0.0.110'
        #host = '0.0.0.0'
        #host = '127.0.0.1'
        #host = localhost
        #port = 52686
        port = 6638
        #port = 6635
        #port = 5000
        #port = 6633
        #port = 5001
        #port = 9998
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest = (host,port)
        tcp.connect(dest)
        #tcp.sendto(msgpack.dump(a),(host,port))
        start_time = time.time()
        print('conectado com controlador')
        #tcp.sendto(msgpack.dump(a),(host,port))
        #PRECISO CONVERTER O PACOTE EM BUFFER PARA PODER ENVIAR VIA SOCKET
        #dado = buffer(a)
        #print (dado)
        #a.encode('utf-8')
        #b = json.dumps(a.__dict__)
        #print ("objeto em Json: ", a)
        
        ######## PEGANDO IP ###############################
        interf = netifaces.interfaces()[1]
        bloc = netifaces.ifaddresses(interf)[2]
        bloc2 = bloc[0]
        ip = bloc2['addr']
        ##################################################
        print "IP user: ",ip
        #f = with open('/home/ramon/pox/pox/forwarding/tempo_1cliente.txt','a') as text_file
        #tcp.sendall(a)
        #path__ = 'home/ramon/pox/pox/forwarding/tempo_1cliente.txt'
        while True:
            try:
                
                print ("-------------------- INICIAR AUTENTICACAO -------")
                # AQUI SERA ENVIADO A CREDENCIAL DO USUARIO
                cred = encrypt_credentials()
                print "tamanha da credencial: ", len(cred)
                #print ("-------------------- credencia em json -------- ",cred)
                #cred = cPickle.dumps(cred)
                #print ("credencial sera enviada enviada ----------------------", cred)
                tcp.sendall(cred)
                time_aut = time.time() - start_time
                print("tempo de aut: --- %s seconds ---" % (time.time() - start_time))
                #save_time(time_aut)
                response = tcp.recv(1024)
                #with open(path__,'a+') as text_file:
                    #text_file.write(repr(ip)+repr(time_aut)+'\n')
                    #text_file.write("teste")
                    #text_file.write(ip+": "+time_aut+'\n')
                    #text_file.close()
                #with open('tempo_1cliente.txt','a') as f:
                print
                print "dados recebidos: ", response
                save_time(ip,time_aut)
                
                
                '''
                with open('tempo_1cliente.txt') as f:
                #f.write('\n'+ip+': '+time_aut)
                    a = "teste.testado 1727384919823"
                    f.flush()
                    f.write('dhwudhaoqwo')
                    f.close()
                '''
                print "dados recebidos: ", response
                if not response:
                    break
            except KeyboardInterrupt:
                print "tchau!"
                break
        
        tcp.close()

    def encrypt_credentials():
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
        m = 222
        #m = 44456
        print ("m a ser cifrado = ",  str(m))
        #print

        func = ElGamalSgFunc(pk, sk)
        c = func.EGCifrar(long(m))
        cifra = {"desc": "autentica", "EGAlfa":c.EGAlfa, "EGBeta": c.EGBeta}
        cj = json.dumps(cifra)
        print "cj :", cj
        #print ("mensagem cifrada: ",c)
        #ALEM DA DECODIFICACAO DO PACOTE, TEM QUE FAZER A DECODIFICACAO DO DADO PRA MOSTRAR O DADO ACIMA
        return cj

    def save_time(ip,time):
        print "DENTRO DA FUNCAO: SAVE_TIME"
        f = open('/home/ramon/pox/pox/forwarding/tempo_1cliente.txt','a')
        ip = json.dumps(ip)
        time = json.dumps(time)
        f.write("\n"+ip+": ")
        f.write(time)
        f.close()
    
    
    #A CONEXAO SOCKET EH ESTABELECIDA AQUI
    cliente_socket_controller(encrypt_credentials,save_time)   
    