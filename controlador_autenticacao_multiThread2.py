from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns

from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import json


import random

############################################### ACHAR UMA SOLUCAO PARA LINHA 348 ######################################################
import json
import sys
sys.path.append('pox/pox/forwarding')
sys.path.append('Autenticacao/br/ufpa/labsc')
#sys.path.append('pox/pox')
from forwarding.CodDecJson import CodDecJson
#verificar a pasta desses imports, porque talvez nao funcione

from threading import Thread
from collections import defaultdict

from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.CodDecEGCifra import CodDecEGCifra
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
from br.ufpa.labsc.libcrypto.nizkp.PTAware import PTAware
from br.ufpa.labsc.libcrypto.nizkp.PTEquivTest import PTEquivTest


log = core.getLogger()

class Controlador(object):  

    def __init__ (self, connection):
        # Switch we'll be adding L2 learning switch capabilities to
        self.connection = connection
        #self.transparent = transparent

        # Our table
        self.macToPort = {}
        #self.mac_to_port = {}

        # We want to hear PacketIn messages, so we listen
        # to the connection
        connection.addListeners(self)

        # We just use this to know when to log a helpful message
        #self.hold_down_expired = _flood_delay == 0

        #log.debug("Initializing LearningSwitch, transparent=%s",
        #          str(self.transparent))

        #self.ip_controller = '10.0.0.110'
        self.ip_addr = IPAddr('10.0.0.115')
        #self.dl_addr = EthAddr('00:00:00:00:05:05')
        self.hw_addr = EthAddr('00:00:09:09:09:09')#self.set_src('00:00:00:00:05:05')
        print "hw_addr: ", self.hw_addr

        #self.last_ack_cliente = {}
        self.cont_pkt_tcp=0
        self.seq_h1 = {}
        self.seq_h1 = dict()
        #self.seq_h1 = 0
        #self.last_ack_cliente=None
        
        self.data_client1 = {}
        self.data_client1 = dict()
        #self.data_client1 = None
        self.data_client2 = {}
        self.data_client2 = dict()
        #self.data_client2 = None
        
        self.beta_received = {}
        self.beta_received = dict()
        #self.beta_received = None
        self.alfa_received = {}
        self.alfa_received = dict()
        #self.alfa_received = None


        #guardar acks enviados
        #self.last_ack_cliente=None
        self.last_ack_cliente = {}
        self.last_ack_cliente = dict()
        self.last_ack_aut2 = None
        self.last_ack_aut3 = None
        self.last_ack_aut4 = None
        self.last_ack_aut5 = None
        self.last_ack_aut6 = None

        self.mac_client = {}
        self.mac_client = dict()
        #self.mac_client = None
        
        self.port_client = None
        #self.port_client = dict()
        #self.port_client = None
        self.ip_client = None

        self.port_controller_switch_cliente = None
        #conta para quantos autenticadores flag FIN foi enviada.
        self.contFIN_flag = 0
        self.contPSH_flag = 0
        #guarda dados da computacao dos autenticadores
        self.data_aut2 = []#{}
        self.data_aut3 = []#{}
        self.data_aut4 = []#{}
        self.data_aut5 = []#{}
        self.data_aut6 = []#{}
        self.data_all_aut =[] #{}
        '''
        self.data_aut2 = dict()
        self.data_aut3 = dict()
        self.data_aut4 = dict()
        self.data_aut5 = dict()
        self.data_aut6 = dict()
        self.data_all_aut = dict()
        '''
        self.i2 = 0 #controla quantas vezes foi add dados do autenticador na lista
        self.i3 = 0
        self.i4 = 0
        self.i5 = 0
        self.i6 = 0
        
        self.last_ip=None
        

        #Threads Client tcp_handle
        self.threads_tcp = {}
        self.threads_tcp = dict()

        # guarda index de cada autenticador que fara a computacao
        self.index_autent = []
        self.autenticadores = {2:'10.0.0.2',3:'10.0.0.3', 4:'10.0.0.4', 5:'10.0.0.5', 6:'10.0.0.6'}

        self.len_data_to_aut=None


        #ALFA E BETA guardados do Cliente 1
        self.ElgAlfa =881395515062685215134221687508086437247886166652208186348118004524042945970938760450044753087854974657415795982731542112603794546333758358341282057755695777949501791883528632953507994368350116881038933232948836272068287831241256302130340876663863499640162773364639034827078561154944479835326045585239144245
        self.ElgaBeta=895121886921517193802040926603312637366348382568919847099005675486567269556797609238082107923962668783978674151653674659457804568680172773322958220028131607062462724728386430325795137417520316613361113650831745705470938380385264164532988375731938566043053283757431310267859227068975511327019434172373575459

        self.ElgAlfa_pet = None
        self.ElgBeta_pet = None


        jsonPK = ''
        with open('/home/ramon/minhaschaves/MinhaChavePublica.json', 'r') as content_file:
            jsonPK = content_file.read()

        # decode PK json
        codDec = CodDecJson()
        
        pk = codDec.deserialize(jsonPK, ElGamalSgPK)

        self.p = pk.getPrimoP()
        self.q = pk.getPrimoQ()
        #print "P: ", self.p
        #print "Q: ", self.q




        jsonSK = ''
        with open('/home/ramon/minhaschaves/MinhaChavePrivada.json', 'r') as content_file:
            jsonSK = content_file.read()
        self.sk = codDec.deserialize(jsonSK, ElGamalSgSK) 

    @classmethod
    def set_src (self,cls, dl_addr = '00:00:09:09:09:09'):
        return cls(OFPAT_SET_DL_SRC, self.dl_addr)

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        packet = event.parsed
        #print "pacote recebido: ", packet
        port = event.port
        self.macToPort[packet.src] = port
        #print "A porta que recebeu e: ", port
        #print "DPID e: ", event.connection.dpid
        if(packet.type == packet.ARP_TYPE):
            #print "PACOTE ARP RECEBIDO: "
            #print "-------------------------------------------------------------------------------------"
            #print packet
            self.handle_arp(packet,port, self.send_Syn_TCP)
        
        #if(packet.type == packet.TCP_TYPE):
        #    print "PACOTE TCP RECEBIDO"
           
        #if(packet.find('ipv4'))
        if(packet.type == packet.IP_TYPE):
            #print "PACOTE IP RECEBIDO"
            pkt_ip = packet.payload
            #print "pacote IPV4: ",pkt_ip
            #print "tamanho PACOTE IP recebido: ", pkt_ip.iplen
            #print "protocolo: ",pkt_ip.protocol

            if(packet.find('tcp')):
                #print "PACOTE TCP recebido:"
                pkt_tcp = pkt_ip.payload
                #print "pkt TCP: ", pkt_tcp
                if((pkt_ip.srcip!='10.0.0.2')&(pkt_ip.srcip!='10.0.0.3')&(pkt_ip.srcip!='10.0.0.4')&(pkt_ip.srcip!='10.0.0.5')&(pkt_ip.srcip!='10.0.0.6')):
                    #self.threading_tcp_handle(pkt_ip.srcip,packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut,self.PetTest)
                    self.handle_tcp(packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut,self.PetTest)
                else:
                    self.handle_tcp_aut(packet,pkt_ip,pkt_tcp,port, self.insert_ack_aut, self.save_last_ack_aut, self.save_data_aut, self.computeM, self.get_data_aut, self.split_data_aut, self.get_data_one_aut, self.theat_list_data, self.send_flagConfirm_to_client)
            #self.handle_tcp(packet.TCP_TYPE):
            
            
    def _send_packet(self,packet_in,out_port):
        '''
        msg = of.ofp_flow_mod()
        msg.data = packet_in
        msg.match.dl_dst = packet.src
        msg.match.dl_src = packet.dst
        msg.actions.append(of.ofp_action_output(port = event.port))
        event.connection.send(msg)
        '''
        
                
        msg = of.ofp_packet_out()
        msg.data = packet_in
        #msg.in_port = out_port
        # Add an action to send to the specified port
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)
        
    #"----------------------------------------------- TERMINA FUNCOES BASICAS CONTROLADOR --------------------------------------------"
    #"----------------------------------------------- COMECA FUNCOES TRATAMENTO PACOTE --------------------------------------------" 
    def handle_arp(self,packet,port,send_Syn_TCP):
        #if ((packet.payload.opcode==1) & (packet.payload.protodst.toStr() == '10.0.0.110')):
        if (packet.payload.opcode==1):
            #print "Requisicao ARP"
            arp_reply = arp()
            arp_reply.hwsrc=EthAddr('00:00:09:09:09:09')
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc=packet.payload.protodst
            arp_reply.protodst=packet.payload.protosrc
            eth = ethernet()
            eth.type = ethernet.ARP_TYPE
            eth.dst = packet.src
            eth.src=EthAddr('ff:ff:fff:ff:ff:ff')
            eth.payload=arp_reply
            #"PRINT ENVIANDO RESPOSTA ARP"
            self._send_packet(eth.pack(),of.OFPP_ALL)
        
        if(packet.payload.opcode==2):
            #arp_aut.hwsrc=EthAddr('00:00:00:00:00:09')
            #        arp_aut.hwdst=EthAddr('ff:ff:ff:ff:ff:ff')
                    #arp_aut.hwdst=EthAddr('00:00:00:00:00:00')
            #        arp_aut.protosrc=self.ip_addr
            
            if(packet.payload.protosrc=='10.0.0.2'):
                self.send_Syn_TCP(packet,port)
            if(packet.payload.protosrc=='10.0.0.3'):
                self.send_Syn_TCP(packet,port)
            if(packet.payload.protosrc=='10.0.0.4'):
                self.send_Syn_TCP(packet,port)
            if(packet.payload.protosrc=='10.0.0.5'):
                self.send_Syn_TCP(packet,port)
            if(packet.payload.protosrc=='10.0.0.6'):    
                self.send_Syn_TCP(packet,port)


    def handle_ipv4(self,packet):
        #print "ipv4"
        print

    def handle_tcp(self,packet,pkt_ip,pkt_tcp,port, random_choose,send_arp_to_aut,PetTest):
        self.cont_pkt_tcp=+1
        if(pkt_tcp.SYN==True):
            #print "PACOTE SYN TCP Recebido"
            
            tcp_pk = tcp()
            tcp_pk.SYN = True
            tcp_pk.ACK = True
            tcp_pk.srcport=6638
            tcp_pk.dstport=pkt_tcp.srcport
            tcp_pk.seq=0
            #self.seq_h1=tcp_pk.seq
            tcp_pk.ack = pkt_tcp.seq+1
            self.last_ack_cliente[pkt_ip.srcip] = tcp_pk.ack
            #self.last_ack_cliente = tcp_pk.ack
            #print "ACK SERA ENVIADO_SYN: ", tcp_pk.ack
            tcp_pk.win=28900
            tcp_pk.off=5
            
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.115')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            ip_pk.set_payload(tcp_pk)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:09:09:09:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
            
            #self.port_client[pkt_ip.srcip] = port
            self._send_packet(ether_pk.pack(),port)
        
        
        if(pkt_tcp.PSH==True):
            self.port_controller_switch_cliente = port
            self.ip_client = pkt_ip.srcip
            print "----------------------------------------------------PACOTE PSH ---------------------------------------------------------"
            #print "PACOTE COM DADOS RECEBIDO"
            print pkt_tcp
            #print "DADOS: ", pkt_tcp.payload
            #print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            #print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            
            self.data_client2[pkt_ip.srcip] = pkt_tcp.payload
            #self.data_client2=pkt_tcp.payload
            
            #print "DADOS PSH: ", self.data_client1
            print "DADOS PSH: ",pkt_tcp.payload
            print "data_client2: ", self.data_client2[pkt_ip.srcip]
            print "------------------------------------------------------ END PSH  ------------------------------------------------------------"
            
            tcp_pkt1 = tcp()
            tcp_pkt1.ACK = True
            tcp_pkt1.srcport=6638
            tcp_pkt1.dstport = pkt_tcp.srcport
            self.port_client = pkt_tcp.srcport
            tcp_pkt1.seq = 1
            self.seq_h1[pkt_ip.srcip] = tcp_pkt1.seq
            #self.seq_h1 = tcp_pkt1.seq
            tcp_pkt1.ack = self.last_ack_cliente[pkt_ip.srcip]+ len(pkt_tcp.payload)
            #tcp_pkt1.ack = self.last_ack_cliente+ len(pkt_tcp.payload)
            tcp_pkt1.win=29200
            tcp_pkt1.off=5
            
            '''
            tcp_pk = tcp()
            ##tcp_pk.PSH = True
            tcp_pk.ACK = True
            tcp_pk.srcport=6633
            tcp_pk.dstport=pkt_tcp.srcport
            tcp_pk.seq=1
            self.seq_h1 = tcp_pk.seq
            ack = len(pkt_tcp.payload)+len(self.data_client2)+1#len(self.data_client2)+ len(pkt_tcp.payload)
            tcp_pk.ack = 1
            print "ACK SERA ENVIADO PSH: ", tcp_pk.ack
            tcp_pk.win=28900
            tcp_pk.off=5
            #tcp_pk.payload="Teste"
            '''



            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.115')
            ip_pk.dstip=pkt_ip.srcip
            self.ip_client = ip_pk.dstip
            ip_pk.protocol=6
            ip_pk.set_payload(tcp_pkt1)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt1)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:09:09:09:09')
            ether_pk.dst = packet.src
            self.mac_client = ether_pk.dst
            ether_pk.type= ethernet.IP_TYPE
        
            #self.port_client[pkt_ip.srcip] = port
            self._send_packet(ether_pk.pack(),port)



            # ---------------------------------------------------------- TRATO DE SEPARA AS ALFA E BETA ----------------------
            #print "DADOS 1: ", self.data_client1
            #print "DADOS 2: ", self.data_client2
            
            cifra = self.data_client1[pkt_ip.srcip]+self.data_client2[pkt_ip.srcip]
            #cifra = self.data_client1+self.data_client2
            
            #print "CIFRA CONCATENADA: ", cifra
            a = cifra.split(",")
            #print "a[0]: ",a[0]
            
            self.beta_received[pkt_ip.srcip] = a[0]
            bet = self.beta_received[pkt_ip.srcip].split(" ")
            self.beta_received[pkt_ip.srcip] = bet[1]
            
            self.alfa_received[pkt_ip.srcip] = a[1]
            alf = self.alfa_received[pkt_ip.srcip].split(" ")
            self.alfa_received[pkt_ip.srcip] = alf[2]
            print "BETA RECEBIDO DO CLIENTE: ", self.beta_received[pkt_ip.srcip]
            print "ALFA RECEBIDO DO CLIENTE: ", self.alfa_received[pkt_ip.srcip]
            self.PetTest(pkt_ip.srcip,self.alfa_received[pkt_ip.srcip],self.beta_received[pkt_ip.srcip],self.ElgAlfa,self.ElgaBeta)
            #print "NOVO ALFA RECEIVED: ", self.alfa_received
            # ---------------------------------------------------------- TERMINO TRATAMENTO ALFA E BETA  RECEBIDOS----------------------------


            # VOU INSERIR AQUI A COMPARACAO DAS CIFRAS, MAS DEPOIS POSSO COLCOAR NUMA FUNCAO
            #---------------------------------------------------------------------------------------------------------------------
            #if((long(self.alfa_received)/self.ElgAlfa == 1) & (long(self.beta_received)/self.ElgaBeta == 1)):
            print "CLIENTE correto. Iniciara PROCESSO DE AUTENTICACAO"
            self.index_autent = self.random_choose()
            self.send_arp_to_aut(self.index_autent)
            
            #else:
                #print "CLIENTE NAO CORRETO. PROCESSO DE AUTENTICACAO TERMINARA"


            # --------------------------------------------------------------------------------------------------------------------    

            #PAREI AQUI. PRECISO COPIAR ESSAS FUNCOES DO CODIGO DO RYU E TESTAR DEPOIS AQUI.
            
            #autent = self.random_choose()
            #self.index_autent = autent
            
            #print "ESTA PASSANDO DA  FUNCAO SELF.RANDOM_CHOOSE"
            
            #self.send_arp_to_aut(autent,datapath)


        if((pkt_tcp.ACK==True)&(len(pkt_tcp) > 100) & (pkt_tcp.PSH==False)):
            print "----------------------------------------------------ACK COM DADOS ---------------------------------------------------------"
            #print "PACOTE COM ACK RECEBIDO:"
            print pkt_tcp
            #print "PACOTE TALVEZ tenha DADOS RECEBIDO"
            #print " POSSIVEIS DADOS: ", pkt_tcp.payload
            self.data_client1[pkt_ip.srcip] = pkt_tcp.payload
            #print "DADOS ACK: ", self.data_client2
            #print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            #print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            #print "PACOTE TODO: ", pkt_tcp
            print "DADOS DO ACK RECEBIDO: ", pkt_tcp.payload
            #print packet.packet.packet.payload
            print "----------------------------------------------------END ACK COM DADOS -------------------------------------------------------"
            

            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6638
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=1
            tcp_pkt.ack = len(pkt_tcp.payload)+self.last_ack_cliente[pkt_ip.srcip]
            #print "ACK SERA ENVIADO DO ACK COM DADOS: ", tcp_pkt.ack
            self.last_ack_cliente[pkt_ip.srcip] = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5


            
            '''
            #self.data_client.append(pkt_tcp.payload)
            #print "dados todos: ", self.data_client1
            #print "TAMANHO DADOS COMPLETO: ", len(self.data_client)
            tcp_pk = tcp()
            #tcp_pk.PSH = True
            tcp_pk.ACK = True
            tcp_pk.srcport=6633
            tcp_pk.dstport=pkt_tcp.srcport
            tcp_pk.seq=1
            self.seq_h1 = tcp_pk.seq
            ack = len(pkt_tcp.payload)
            tcp_pk.ack = ack+1#len(self.data_client1)+len(self.data_client2)+1
            print "ACK SERA ENVIADO no ACK DADOS: ", tcp_pk.ack
            #self.data_client1 = len(tcp_pk.payload)
            tcp_pk.win=28900
            tcp_pk.off=5
            #tcp_pk.payload="Teste"
            '''
            
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.115')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:09:09:09:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
            
            print "----------------------------------------- DADOS 1 e 2   ------------------------------------------------------"
            #print "DADOS 1: ", self.data_client1
            #print "DADOS 2: ", self.data_client2
            
            self._send_packet(ether_pk.pack(),port)
        #print "tcp"

    
    def handle_tcp_aut(self,packet,pkt_ip,pkt_tcp,port, insert_ack_aut, save_last_ack_aut, save_data_aut, computeM, get_data_aut, split_data_aut, get_data_one_aut, theat_list_data, send_flagConfirm_to_client):
        if((pkt_tcp.SYN==True)&(pkt_tcp.ACK==True)):
            #AQUI VOU ENVIAR O ACK DO SYN-ACK E OS DADOS JA. DEPOIS POSSO COLOCAR O ENVIAR PSH NUMA FUNCAO
            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6638
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=1
            seq = tcp_pkt.seq
            tcp_pkt.ack = pkt_tcp.seq+1
            ack = tcp_pkt.ack
            #self.last_ack_cliente = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5

                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.115')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:09:09:09:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)
        
            ###################################################################################################
            #ENVIOU DOS DADOS NO MESMO IF DO ACK                                                              #
            ###################################################################################################
            dados_send = []
            '''
            print "ALFA RECEBIDO: ",self.alfa_received
            print "ALFA GUARDADO: ", self.ElgAlfa
            print "#**#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#**#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
            div_alfa = long(self.alfa_received)/long(self.ElgAlfa)
            print "ALFA QUE SERA ENVIADO: ", div_alfa
            '''
            #self.alfa_received[self.ip_client] = str(self.alfa_received[self.ip_client])
            dados_send.append(self.ElgAlfa_pet)
            dados_send.append(self.index_autent)
            tcp_pkt = tcp()
            tcp_pkt.PSH= True
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6638
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq= seq#1
            tcp_pkt.ack = ack#pkt_tcp.ack
            self.save_last_ack_aut(pkt_ip.srcip,tcp_pkt.ack)# = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5
            dados_send= json.dumps(dados_send)
            tcp_pkt.payload=dados_send
            self.len_data_to_aut= len(tcp_pkt.payload)
                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.115')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:09:09:09:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)
            #TERMINA ENVIO DADOS PARA AUTENTICADORES



        if(pkt_tcp.PSH==True):
            if(pkt_ip.srcip!=self.last_ip):
                self.contPSH_flag = self.contPSH_flag +1
            print "contPSH: ",self.contPSH_flag
            print "PACOTE PSH RECEBIDO NO handle_TCP_AUT:"
            print pkt_tcp
            print pkt_tcp.payload
            print"PAYLOAD DIVIDIDO, payload[0]: ", pkt_tcp.payload[0]
            print"PAYLOAD DIVIDIDO, payload[1]: ", pkt_tcp.payload[1]
            self.save_data_aut(pkt_ip.srcip,pkt_tcp.payload)
            
            dat__ = self.get_data_one_aut(pkt_ip.srcip)
            
            dat__2 = self.split_data_aut(dat__)
            print "DAT__", dat__
            
            
            #print "separado 1: ", dat__2[0]
            #print "separado 2: ", dat__2[1] 
            
            my_lst = ''.join(map(str, dat__2[0]))
            my_lst = long(my_lst)
            print(my_lst)
            
            my_lst_str = ''.join(map(str, dat__2[1]))
            my_lst_str = long(my_lst_str)
            print(my_lst_str)

            self.data_all_aut.append(my_lst)
            self.data_all_aut.append(my_lst_str)

            #self,di,l0,dj,l1,dk,l2,c,p
            
            '''
            if(self.contPSH_flag==3):
                self.data_all_aut = long(self.data_all_aut)
                m = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],long(self.ElgaBeta),long(p))
                print "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
                print "MENSAGEM FINAL COMPUTADA: ", m
                print "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
            '''
            '''
            ab1 = self.theat_list_data(dat__2[0])
            ab2 = self.theat_list_data(dat__2[1])
            print "ab1: ",ab1
            print "ab2: ",ab2
            
            
            print "DADOS DEPOIS DE FEITO TRATAMENTO: ", dat__
            #print "DADOS DEPOIS DE SPLIT: ", dat__2
            #print "INDICE 1 DADOS depois do tratamento: ", dat__[1]
            #print "INDICE 2 DADOS depois do tratamento: ", dat__[2]
            part1 = dat__[1]
            part2 = self.theat_list_data(dat__[3:])
            print "DADOS SEPARADOS 1 : ",part1
            print "DADOS SEPARADOS 2 : ",part2
            '''
            #a__ = self.get_data_one_aut(pkt_ip.srcip)
            #print "recuperando DADOS do autenticador: ", a__
            #ata = self.split_data_aut(a__)
            #self.data_all_aut.append(ata)
            #print "DADOS AUTENTICADOR,POS SPLIT: ", ata
            
            ack_ = len(pkt_tcp.payload)
            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6638
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq= self.len_data_to_aut+1
            tcp_pkt.ack = self.insert_ack_aut(pkt_ip.srcip)+ack_            #len(pkt_tcp.payload)+1 #AQUI VAI ENTRAR A FUNCAO QUE INSERE O ACK DE ACORDO COM AUTENTICADOR
            self.save_last_ack_aut(pkt_ip.srcip,tcp_pkt.ack) #= tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5

                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.115')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            self.last_ip = ip_pk.srcip

            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:09:09:09:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)

            #FAZER COM QUE ENTRE NESSA FUNCAO E COMPUTE O FINAL.
            
            if(self.contPSH_flag>=3):
                #if(self.contPSH_flag==3):
                print "*****************************************##########################################******************************"
                #self.data_all_aut = long(self.data_all_aut)
                print "TODOS OS LAGRANGES E COMPUT AUTENTICADORES: ", self.data_all_aut
                print "self.data_all_aut[1]: ", self.data_all_aut[1]
                print "self.data_all_aut[3]: ", self.data_all_aut[3]
                print "self.data_all_aut[5]: ", self.data_all_aut[5]
                m = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],int(self.ElgBeta_pet),int(self.p))
                m_b_guard = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],int(self.ElgaBeta),int(self.p))
                m_b_receiv =  self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],int(self.beta_received[self.ip_client]),int(self.p))
                '''
                m_long = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],long(self.ElgBeta_pet),long(self.p))
                m_b_guard_long = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],long(self.ElgaBeta),long(self.p))
                m_b_receiv_long =  self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],long(self.beta_received[self.ip_client]),long(self.p))
                '''
                #print "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
                print "MENSAGEM FINAL COMPUTADA m_pet_int: ", m
                print "MENSAGEM FINAL COMPUTADA m_b_guard_int: ", m_b_guard
                print "MENSAGEM FINAL COMPUTADA m_b_receiv_int: ", m_b_receiv
                '''
                print "MENSAGEM FINAL COMPUTADA m_pet_long: ", m_long
                print "MENSAGEM FINAL COMPUTADA m_b_guard_long: ", m_b_guard_long
                print "MENSAGEM FINAL COMPUTADA m_b_receiv_long: ", m_b_receiv_long
                '''
                #self.send_flagConfirm_to_client(m,self.port_controller_switch_cliente)
                #print "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
                
                '''
                self.get_data_aut()
                print"#####################---------------------------------#######################################################"
                print "DADOS DE TODOS OS AUTENTICADORES:"
                print "aqui: ", self.data_all_aut
                #mensagem_final = self.computeM(di,l0,dj,l1,dk,l2,c,p)
                #mensagem_final = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],self.beta_received,self.p)
                #print "MENSAGEM FINAL COMPUTADA PELO CONTROLADOR: ",mensagem_final
                print"#####################---------------------------------#######################################################"
                '''
            
            
            ## ENVIAR FIN-ACK AQUI
        if(pkt_tcp.FIN ==True):
            fin = tcp()
            #tcp_pkt = tcp()
            fin.FIN = True
            fin.ACK = True
            fin.srcport=6638
            fin.dstport=pkt_tcp.srcport
            fin.seq= pkt_tcp.ack#pkt_tcp.seq
            fin.ack = pkt_tcp.seq#pkt_tcp.ack+1            
            self.save_last_ack_aut(pkt_ip.srcip,fin.ack) #= tcp_pkt.ack
            fin.win=29200
            fin.off=5


            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.115')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(fin)
            ip_pk.iplen = ipv4.MIN_LEN + len(fin)
            ip_pk.csum=0
            
            ether_pk_ = ethernet()
            ether_pk_.set_payload(ip_pk)
            ether_pk_.src=EthAddr('00:00:09:09:09:09')
            ether_pk_.dst = packet.src
            ether_pk_.type= ethernet.IP_TYPE

            self._send_packet(ether_pk_.pack(),port)
        


        if((pkt_tcp.ACK==True)&(len(pkt_tcp) > 150) & (pkt_tcp.PSH==False)):
            #print "---------------------------------------ACK COM DADOS  DO AUTENTICADOR ---------------------------------------------"
            #print "PACOTE COM ACK RECEBIDO:"
            print pkt_tcp
            #print "PACOTE TALVEZ tenha DADOS RECEBIDO"
            self.save_data_aut(pkt_ip.srcip,pkt_tcp.payload)
            #print " POSSIVEIS DADOS: ", pkt_tcp.payload
            #self.data_client1 = pkt_tcp.payload
            #print "DADOS ACK: ", self.data_client2
            ack_ack = len(pkt_tcp.payload)
            #print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            #print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            #print "PACOTE TODO: ", pkt_tcp
            #print "DADOS DO ACK RECEBIDO: ", pkt_tcp.payload
            #print packet.packet.packet.payload
            #print "--------------------------------------------END ACK COM DADOS do Autenticador -----------------------------------"
            

            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6638
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=self.len_data_to_aut+1
            tcp_pkt.ack = self.insert_ack_aut(pkt_ip.srcip)+ack_ack #AQUI VAI ENTRAR A FUNCAO QUE INSERE ACK DE ACORDO COM IP AUTENTICADOR
            self.save_last_ack_aut(pkt_ip.srcip,tcp_pkt.ack)
            #self.last_ack_aut3 = tcp_pkt.ack
            print "ACK SERA ENVIADO DO ACK COM DADOS: ", tcp_pkt.ack
            #self.last_ack_cliente = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5


                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.115')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:09:09:09:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
            
                       
            self._send_packet(ether_pk.pack(),port)




    # -------------------------------------- AQUI TENHO QUE INSERIR (COLAR) AS FUNCOES QUE SAO DE AUTENTICACAO INSERIDAS NO RYU --------------
    #def
    def random_choose(self):
        controllers = random.sample(range(2,6), 3) #porque o ID dos autenticadores esta entre 2 e 6
        print "------------------------------------------- controladores escolhidos: ----------------------------------------------"
        print "controladores escolhidos: ", controllers
        #print "tipo :", type(controllers[0])
        return controllers

    def send_arp_to_aut(self,vector):
        #print "ESTA ENTRANDO NA FUNCAO SEND_ARP_TO_AUT ----------------------------------------------------------------"
        for i in vector:
            #print "ENTRANDO primeiro FOR"
            #print "valor de i: ",i
            for j in self.autenticadores.keys():
                #print "Entrando segundo for"
                #print "valor de J: ",j
                #print "valor de I dentro de for j: ",i
                if (i == j):
                    ip = self.autenticadores[j]
                    print "-------------------------------------------------IP sera enviado ARP REQ ----------------------------------------------- ", ip
                    port = i
                    print "porta e: ", port
                    arp_aut = arp()
                    arp_aut.opcode=1 #request
                    arp_aut.hwsrc=EthAddr('00:00:09:09:09:09')
                    arp_aut.hwdst=EthAddr('ff:ff:ff:ff:ff:ff')
                    #arp_aut.hwdst=EthAddr('00:00:00:00:00:00')
                    arp_aut.protosrc=self.ip_addr
                    arp_aut.protodst=IPAddr(ip)

                    ether = ethernet()
                    ether.type=ethernet.ARP_TYPE
                    ether.dst=EthAddr('ff:ff:ff:ff:ff:ff')
                    ether.src=EthAddr('00:00:09:09:09:09')
                    ether.payload=arp_aut
                    self._send_packet(ether.pack(),port)
    


    
    def send_flagConfirm_to_client(self, m,port):
        a = "SIM. Autenticado"
        tcp_pkt = tcp()
        tcp_pkt.PSH = True
        tcp_pkt.ACK = True
        tcp_pkt.srcport=6638
        tcp_pkt.dstport=self.port_client
        tcp_pkt.seq= self.seq_h1#1
        seq = tcp_pkt.seq
        tcp_pkt.ack = self.last_ack_cliente#pkt_tcp.seq+1
        ack = tcp_pkt.ack
        #self.last_ack_cliente = tcp_pkt.ack
        tcp_pkt.win=29200
        tcp_pkt.off=5
        tcp_pkt.set_payload(a)

                       
        ip_pk = ipv4()
        #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
        ip_pk.protocol= ipv4.TCP_PROTOCOL
        ip_pk.srcip=IPAddr('10.0.0.115')
        ip_pk.dstip=self.ip_client#pkt_ip.srcip
        print "ip destino: ", ip_pk.dstip
        ip_pk.protocol=6
        #ip_pk.set_payload(tcp_pk)
        ip_pk.set_payload(tcp_pkt)
        ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
        ip_pk.csum=0
            
        ether_pk = ethernet()
        ether_pk.set_payload(ip_pk)
        ether_pk.src=EthAddr('00:00:09:09:09:09')
        ether_pk.dst = packet.src
        ether_pk.type= ethernet.IP_TYPE

        self._send_packet(ether_pk.pack(),port)
        
        
        
        '''
        tcp_pkt = tcp()
        m = json.dumps(m)
        tcp_pkt.set_payload('sim')
        tcp_pkt.PSH = True
        tcp_pkt.ACK = True
        tcp_pkt.srcport=6633
        tcp_pkt.dstport=self.port_client
        tcp_pkt.seq= self.seq_h1
        #seq = tcp_pkt.seq
        tcp_pkt.ack = self.last_ack_cliente     #pkt_tcp.seq+1
        #ack = tcp_pkt.ack
        #self.last_ack_cliente = tcp_pkt.ack
        tcp_pkt.win=29200
        tcp_pkt.off=5

                       
        ip_pk = ipv4()
        #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
        ip_pk.protocol= ipv4.TCP_PROTOCOL
        ip_pk.srcip=IPAddr('10.0.0.110')
        ip_pk.dstip= self.ip_client
        ip_pk.protocol=6
        #ip_pk.set_payload(tcp_pk)
        ip_pk.set_payload(tcp_pkt)
        #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
        #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
        ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
        ip_pk.csum=0
            
        ether_pk = ethernet()
        ether_pk.set_payload(ip_pk)
        ether_pk.src=EthAddr('00:00:00:00:00:09')
        ether_pk.dst = self.mac_client
        ether_pk.type= ethernet.IP_TYPE

        self._send_packet(ether_pk.pack(),port)
        '''

    ########################################################################################################################################
    ################################################# HERE THREAT SOME CASES OF AUTENTICATORS TCP PACKETS ##################################
    ########################################################################################################################################
    ########################################################################################################################################
    ########################################################################################################################################
    ########################################################################################################################################


    #SEND SYN TO AUT
    def send_Syn_TCP(self,packet,port):
        tcp_pk = tcp()
        tcp_pk.SYN = True
        tcp_pk.srcport=6638
        tcp_pk.dstport=5000
        tcp_pk.seq=0
        #self.seq_h1=tcp_pk.seq
        tcp_pk.ack = 0
        #self.last_ack_cliente = tcp_pk.ack
        #print "ACK SERA ENVIADO_SYN: ", tcp_pk.ack
        tcp_pk.win=28900
        tcp_pk.off=5
            
        ip_pk = ipv4()
        #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
        ip_pk.protocol= ipv4.TCP_PROTOCOL
        ip_pk.srcip=IPAddr('10.0.0.115')
        ip_pk.dstip=packet.payload.protosrc
        ip_pk.protocol=6
        ip_pk.set_payload(tcp_pk)
        ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
        ip_pk.csum=0
            
        ether_pk = ethernet()
        ether_pk.set_payload(ip_pk)
        ether_pk.src=EthAddr('00:00:09:09:09:09')
        ether_pk.dst = packet.src
        ether_pk.type= ethernet.IP_TYPE
            
        print "SEND SYN PARA : ",ip_pk.dstip
        self._send_packet(ether_pk.pack(),port)

    
    
    def insert_ack_aut(self,ip):
        if(ip=='10.0.0.2'):
            return self.last_ack_aut2

        if(ip=='10.0.0.3'):
            return self.last_ack_aut3

        if(ip=='10.0.0.4'):
            return self.last_ack_aut4

        if(ip=='10.0.0.5'):
            return self.last_ack_aut5

        if(ip=='10.0.0.6'):
            return self.last_ack_aut6

    
    
    def save_last_ack_aut(self,ip,ack):
        if(ip=='10.0.0.2'):
            self.last_ack_aut2 = ack
        
        if(ip=='10.0.0.3'):
            self.last_ack_aut3 = ack

        if(ip=='10.0.0.4'):
            self.last_ack_aut4 = ack

        if(ip=='10.0.0.5'):
            self.last_ack_aut5 = ack

        if(ip=='10.0.0.6'):
            self.last_ack_aut6 = ack



    def save_data_aut(self,ip,data):
        if(ip=='10.0.0.2'):
            self.i2+=1
            self.data_aut2.append(data)
            if(self.i2==2):
                self.data_aut2 = self.data_aut2[0]+self.data_aut2[1]
        if(ip=='10.0.0.3'):
            self.i3+=1
            self.data_aut3.append(data)
            if(self.i3==2):
                self.data_aut3 = self.data_aut3[0]+self.data_aut3[1]

        if(ip=='10.0.0.4'):
            self.i4+=1
            self.data_aut4.append(data)
            if(self.i4==2):
                self.data_aut4 = self.data_aut4[0]+self.data_aut4[1]

        if(ip=='10.0.0.5'):
            self.i5+=1
            self.data_aut5.append(data)
            if(self.i5==2):
                self.data_aut5 = self.data_aut5[0]+self.data_aut5[1]

        if(ip=='10.0.0.6'):
            self.i6+=1
            self.data_aut6.append(data)
            if(self.i6==2):
                self.data_aut6 = self.data_aut6[0]+self.data_aut6[1]
        

    def order_data_aut(self,ip):
        if(ip=='10.0.0.2'):
            cifra = self.data_aut2[0]+self.data_aut2[1]
            #print "CIFRA CONCATENADA: ", cifra
            a = cifra.split(",")
            #print "a[0]: ",a[0]
            
            self.beta_received = a[0]
            self.data_aut2 = a[0]

            bet = self.beta_received.split(" ")
            dat = self.data_aut2.split(" ")

            self.beta_received = bet[1]
            
            self.alfa_received = a[1]
            alf = self.alfa_received.split(" ")
            self.alfa_received = alf[2]

    
    def split_data_aut(self,data):
        data_threated = []
        part1 = []
        part2 = []
        a = data[0:data.index(",")]
        b = data[data.index(","):]
        for n in a:#a[0]:
            try:
                part1.append(int(n)) 
            except:
                pass

        for j in b:#a[1]:
            try:
                part2.append(int(j)) 
            except:
                pass
        
        #print "PART1: ", part1
        #print "PART2: ",part2

        data_threated.append(part1)
        data_threated.append(part2)
        return data_threated


    def get_data_aut(self):
        for i in self.autenticadores.keys():
            for j in self.index_autent:
                if((j==i)&(i==2)):
                    self.data_all_aut.append(self.data_aut2[0])
                    self.data_all_aut.append(self.data_aut2[1])
                if((j==i)&(i==3)):
                    self.data_all_aut.append(self.data_aut3[0])
                    self.data_all_aut.append(self.data_aut3[1])
                if((j==i)&(i==4)):
                    self.data_all_aut.append(self.data_aut4[0])
                    self.data_all_aut.append(self.data_aut4[1])
                if((j==i)&(i==5)):
                    self.data_all_aut.append(self.data_aut5[0])
                    self.data_all_aut.append(self.data_aut5[1])
                if((j==i)&(i==6)):
                    self.data_all_aut.append(self.data_aut6[0])
                    self.data_all_aut.append(self.data_aut6[1])
                #if(self.autenticadores.keys==2):
                #    self.data_all_aut.append(self.data_aut6)
    


    def get_data_one_aut(self,ip):
        if(ip=='10.0.0.2'):
            return self.data_aut2
        
        if(ip=='10.0.0.3'):
            return self.data_aut3

        if(ip=='10.0.0.4'):
            return self.data_aut4

        if(ip=='10.0.0.5'):
            return self.data_aut5

        if(ip=='10.0.0.6'):
            return self.data_aut6



    def theat_list_data(self,lista):
        
        #print "LISTA DENTRO get_index_aut: ", lista
        #print "Lista[0]: ", lista[0]
        #print "Lista[1]: ", lista[1]
        #print "Lista[2]: ", lista[2]
        aut_index=[]
        
        for n in lista-1:
            try:
                aut_index.append(int(n)) 
            except:
                pass
        return aut_index
### ------------------------------------------------ FUNCOES DE CRIPTOGRAFIA --------------------------------------------------###
    def computeM(self,di,l0,dj,l1,dk,l2,c,p):
        print "**************************************************************************************************************************"
        print "*--------------------------------------------- Dentro da funcao computerM ----------------------------------------------**"
        print "##########################################################################################################################"
        print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
        print "di: ", di
        print "l0: ", l0
        print
        print "dj: ", dj
        print "l1: ", l1
        print
        print "dk: ", dk
        print "l2: ", l2
        print
        da = pow(di,l0,p)
        db = pow(dj, l1,p)
        dc = pow(dk, l2,p)
        j = (da*db*dc)
        m = (pow(j,p-2,p)*c)%p
        print "MENSAGEM COMPUTADA: ", m
        print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
        print "##########################################################################################################################" 
        print "**************************************************************************************************************************"
        return m


    def PetTest(self,ip,alfaReceived,betaReceived,alfaSaved,betaSaved):
        self.ElgAlfa_pet = long(self.alfa_received[ip]) * pow(long(self.ElgAlfa),long(self.sk.p)-2,long(self.sk.p))
        self.ElgBeta_pet = long(self.beta_received[ip]) * pow(long(self.ElgaBeta),long(self.sk.p)-2,long(self.sk.p))


    def threading_tcp_handle(self,ip,packet,pkt_ip,pkt_tcp,port,random_choose,send_arp_to_aut,PetTest):
        ip = str(ip)
        #if(self.threads_tcp[ip].getName() != ip):
        if not (ip in self.threads_tcp):
            print "DENTRO DA FUNCAO threading_tcp_handle"
            #self.threads_tcp_handle[ip] =  MyThread(self.handle_tcp(packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut,self.PetTest))#Thread(target=handle_tcp(), args())
            #self.threads_tcp[ip] = Thread(target=Controlador.handle_tcp,args=(packet,pkt_ip,pkt_tcp,port,random_choose,send_arp_to_aut,PetTest))
            self.threads_tcp[ip] = MyThread(self.handle_tcp(packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut,self.PetTest))
            self.threads_tcp[ip].setName(ip)
            print "apos criar objeto de MyThread"
            #self.threading_tcp_handle[ip].start()
            self.threads_tcp[ip].start()
            print "Depois de iniciar a thread do cliente por IP"
        
        else:
            #self.threading_tcp_handle[ip].reOpen_func(packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut,self.PetTest)
            self.threads_tcp.reOpen_func(ip,self.threads_tcp[ip],self.handle_tcp,packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut,self.PetTest)
            #self.reOpen_func(ip,packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut,self.PetTest)
            #self.threads_tcp[ip].reOpen_func()
            
            #self.threads_tcp[ip].reOpen_func()
            #self.reOpen_func(ip)

    def reOpen_func(self,ip,packet,pkt_ip,pkt_tcp,port,random_choose,send_arp_to_aut,PetTest):
         self.threads_tcp[ip]
         #self.tcp_handle(packet,pkt_ip,pkt_tcp,port,random_choose,send_arp_to_aut,PetTest)
### ------------------------------------------------- FUNCAO de Inicializacao do controlador ---------------------------------###
def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Controlador(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)






class MyThread(Thread):
    def __init__(tcp_func,packet,pkt_ip,pkt_tcp,port,random_choose,send_arp_to_aut,PetTest):    
        tcp_func(packet,pkt_ip,pkt_tcp,port,random_choose,send_arp_to_aut,PetTest)

    #nessa funcao passar de novo todos parametros da funcao tcp_handle    
    def reOpen_func(ip,array_thread,tcp_handle,packet,pkt_ip,pkt_tcp,port,random_choose,send_arp_to_aut,PetTest):
        array_thread[ip].tcp_handle(packet,pkt_ip,pkt_tcp,port,random_choose,send_arp_to_aut,PetTest)

