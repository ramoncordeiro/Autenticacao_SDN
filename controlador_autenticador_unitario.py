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

#verificar a pasta desses imports, porque talvez nao funcione
'''
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.CodDecEGCifra import CodDecEGCifra
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
from br.ufpa.labsc.libcrypto.nizkp.PTAware import PTAware
from br.ufpa.labsc.libcrypto.nizkp.PTEquivTest import PTEquivTest
'''

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
        self.ip_addr = IPAddr('10.0.0.110')
        #self.dl_addr = EthAddr('00:00:00:00:05:05')
        self.hw_addr = EthAddr('00:00:00:00:00:09')#self.set_src('00:00:00:00:05:05')
        print "hw_addr: ", self.hw_addr

        self.cont_pkt_tcp=0
        self.seq_h1 = 0
        self.last_ack_cliente=None
        self.last_ack_aut2 = None
        self.last_ack_aut3 = None
        self.last_ack_aut4 = None
        self.last_ack_aut5 = None
        self.last_ack_aut6 = None
        
        
        self.data_client1 = None
        self.data_client2 = None
        self.beta_received = None
        self.alfa_received = None

        self.index_autent = []
        self.autenticadores = {2:'10.0.0.2',3:'10.0.0.3', 4:'10.0.0.4', 5:'10.0.0.5', 6:'10.0.0.6'}

        self.len_data_to_aut=None


        #ALFA E BETA guardados do Cliente 1
        self.ElgAlfa =881395515062685215134221687508086437247886166652208186348118004524042945970938760450044753087854974657415795982731542112603794546333758358341282057755695777949501791883528632953507994368350116881038933232948836272068287831241256302130340876663863499640162773364639034827078561154944479835326045585239144245
        self.ElgaBeta=895121886921517193802040926603312637366348382568919847099005675486567269556797609238082107923962668783978674151653674659457804568680172773322958220028131607062462724728386430325795137417520316613361113650831745705470938380385264164532988375731938566043053283757431310267859227068975511327019434172373575459
    @classmethod
    def set_src (self,cls, dl_addr = '00:00:00:00:00:09'):
        return cls(OFPAT_SET_DL_SRC, self.dl_addr)

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        packet = event.parsed
        #print "pacote recebido: ", packet
        port = event.port
        self.macToPort[packet.src] = port
        print "A porta que recebeu e: ", port
        print "DPID e: ", event.connection.dpid
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
                if(pkt_ip.srcip=='10.0.0.1'):
                    self.handle_tcp(packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut)
                else:
                    self.handle_tcp_aut(packet,pkt_ip,pkt_tcp,port)
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
            print "Requisicao ARP"
            arp_reply = arp()
            arp_reply.hwsrc=EthAddr('00:00:00:00:00:09')
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc=packet.payload.protodst
            arp_reply.protodst=packet.payload.protosrc
            eth = ethernet()
            eth.type = ethernet.ARP_TYPE
            eth.dst = packet.src
            eth.src=EthAddr('ff:ff:fff:ff:ff:ff')
            eth.payload=arp_reply
            "PRINT ENVIANDO RESPOSTA ARP"
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
        print "ipv4"

    def handle_tcp(self,packet,pkt_ip,pkt_tcp,port, random_choose,send_arp_to_aut):
        self.cont_pkt_tcp=+1
        if(pkt_tcp.SYN==True):
            print "PACOTE SYN TCP Recebido"
            
            tcp_pk = tcp()
            tcp_pk.SYN = True
            tcp_pk.ACK = True
            tcp_pk.srcport=6633
            tcp_pk.dstport=pkt_tcp.srcport
            tcp_pk.seq=0
            #self.seq_h1=tcp_pk.seq
            tcp_pk.ack = pkt_tcp.seq+1
            self.last_ack_cliente = tcp_pk.ack
            print "ACK SERA ENVIADO_SYN: ", tcp_pk.ack
            tcp_pk.win=28900
            tcp_pk.off=5
            
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            ip_pk.set_payload(tcp_pk)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
            
            
            self._send_packet(ether_pk.pack(),port)
        
        
        if(pkt_tcp.PSH==True):
            print "----------------------------------------------------PACOTE PSH ---------------------------------------------------------"
            print "PACOTE COM DADOS RECEBIDO"
            print pkt_tcp
            #print "DADOS: ", pkt_tcp.payload
            print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            self.data_client2=pkt_tcp.payload
            #print "DADOS PSH: ", self.data_client1
            print "DADOS PSH: ",pkt_tcp.payload
            print "data_client2: ", self.data_client2
            print "------------------------------------------------------ END PSH  ------------------------------------------------------------"
            
            tcp_pkt1 = tcp()
            tcp_pkt1.ACK = True
            tcp_pkt1.srcport=6633
            tcp_pkt1.dstport = pkt_tcp.srcport
            tcp_pkt1.seq = 1
            tcp_pkt1.ack = self.last_ack_cliente+ len(pkt_tcp.payload)
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
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            ip_pk.set_payload(tcp_pkt1)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt1)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
        
            
            self._send_packet(ether_pk.pack(),port)



            # ---------------------------------------------------------- TRATO DE SEPARA AS ALFA E BETA ----------------------
            #print "DADOS 1: ", self.data_client1
            #print "DADOS 2: ", self.data_client2
            cifra = self.data_client1+self.data_client2
            #print "CIFRA CONCATENADA: ", cifra
            a = cifra.split(",")
            #print "a[0]: ",a[0]
            
            self.beta_received = a[0]
            bet = self.beta_received.split(" ")
            self.beta_received = bet[1]
            
            self.alfa_received = a[1]
            alf = self.alfa_received.split(" ")
            self.alfa_received = alf[2]
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
            #print "----------------------------------------------------ACK COM DADOS ---------------------------------------------------------"
            #print "PACOTE COM ACK RECEBIDO:"
            print pkt_tcp
            #print "PACOTE TALVEZ tenha DADOS RECEBIDO"
            #print " POSSIVEIS DADOS: ", pkt_tcp.payload
            self.data_client1 = pkt_tcp.payload
            #print "DADOS ACK: ", self.data_client2
            #print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            #print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            #print "PACOTE TODO: ", pkt_tcp
            #print "DADOS DO ACK RECEBIDO: ", pkt_tcp.payload
            #print packet.packet.packet.payload
            #print "----------------------------------------------------END ACK COM DADOS -------------------------------------------------------"
            

            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=1
            tcp_pkt.ack = len(pkt_tcp.payload)+self.last_ack_cliente
            #print "ACK SERA ENVIADO DO ACK COM DADOS: ", tcp_pkt.ack
            self.last_ack_cliente = tcp_pkt.ack
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
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
            
            print "----------------------------------------- DADOS 1 e 2   ------------------------------------------------------"
            #print "DADOS 1: ", self.data_client1
            #print "DADOS 2: ", self.data_client2
            
            self._send_packet(ether_pk.pack(),port)
        #print "tcp"

    
    def handle_tcp_aut(self,packet,pkt_ip,pkt_tcp,port):
        if((pkt_tcp.SYN==True)&(pkt_tcp.ACK==True)):
            #AQUI VOU ENVIAR O ACK DO SYN-ACK E OS DADOS JA. DEPOIS POSSO COLOCAR O ENVIAR PSH NUMA FUNCAO
            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=1
            tcp_pkt.ack = pkt_tcp.seq+1
            ack = tcp_pkt.ack
            seq = tcp_pkt.seq
            #self.last_ack_cliente = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5

                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)
        
            ###################################################################################################
            #ENVIOU DOS DADOS NO MESMO IF DO ACK                                                              #
            ###################################################################################################
            dados_send = []
            dados_send.append(self.alfa_received)
            dados_send.append(self.index_autent)
            tcp_pkt = tcp()
            tcp_pkt.PSH= True
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq= seq
            tcp_pkt.ack = ack
            self.last_ack_aut3 = tcp_pkt.ack
            #self.last_ack_cliente = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5
            dados_send= json.dumps(dados_send)
            tcp_pkt.payload=dados_send
            self.len_data_to_aut= len(tcp_pkt.payload)
                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)
            #TERMINA ENVIO DADOS PARA AUTENTICADORES



        if(pkt_tcp.PSH==True):
            print "PACOTE PSH RECEBIDO NO handle_TCP_AUT:"
            print pkt_tcp
            print "PAYLOAD PSH DO AUT: ", pkt_tcp.payload
            print "PAYLOAD LEN: ",len(pkt_tcp.payload)
            ack_ = len(pkt_tcp.payload)
            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq= self.len_data_to_aut+1
            tcp_pkt.ack = self.last_ack_aut3+ack_
            print "ACK DOS DADOS RECEBIDOS do AUTENTICADOR: ", tcp_pkt.ack
            #self.last_ack_cliente = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5

                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)


        if((pkt_tcp.ACK==True)&(len(pkt_tcp) > 150) & (pkt_tcp.PSH==False)):
            print "---------------------------------------ACK COM DADOS  DO AUTENTICADOR ---------------------------------------------"
            print "PACOTE COM ACK RECEBIDO:"
            print pkt_tcp
            print "PACOTE TALVEZ tenha DADOS RECEBIDO"
            #print " POSSIVEIS DADOS: ", pkt_tcp.payload
            #self.data_client1 = pkt_tcp.payload
            #print "DADOS ACK: ", self.data_client2
            ack_ack = len(pkt_tcp.payload)
            print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            print "PACOTE TODO: ", pkt_tcp
            print "DADOS DO ACK RECEBIDO: ", pkt_tcp.payload
            #print packet.packet.packet.payload
            print "--------------------------------------------END ACK COM DADOS do Autenticador -----------------------------------"
            

            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=self.len_data_to_aut+1
            tcp_pkt.ack = self.last_ack_aut3+ack_ack
            self.last_ack_aut3 = tcp_pkt.ack
            print "ACK SERA ENVIADO DO ACK COM DADOS: ", tcp_pkt.ack
            #self.last_ack_cliente = tcp_pkt.ack
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
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
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
        ###for i in vector:
            #print "ENTRANDO primeiro FOR"
            #print "valor de i: ",i
            ###for j in self.autenticadores.keys():
                #print "Entrando segundo for"
                #print "valor de J: ",j
                #print "valor de I dentro de for j: ",i
                ###if (i == j):
                    ###ip = self.autenticadores[j]
        #print "-------------------------------------------------IP sera enviado ARP REQ ----------------------------------------------- ", ip
        port = 3
        print "porta e: ", port
        arp_aut = arp()
        arp_aut.opcode=1 #request
        arp_aut.hwsrc=EthAddr('00:00:00:00:00:09')
        arp_aut.hwdst=EthAddr('ff:ff:ff:ff:ff:ff')
                    #arp_aut.hwdst=EthAddr('00:00:00:00:00:00')
        arp_aut.protosrc=self.ip_addr
        arp_aut.protodst=IPAddr('10.0.0.3')

        ether = ethernet()
        ether.type=ethernet.ARP_TYPE
        ether.dst=EthAddr('ff:ff:ff:ff:ff:ff')
        ether.src=EthAddr('00:00:00:00:00:09')
        ether.payload=arp_aut
        self._send_packet(ether.pack(),port)

    def send_Syn_TCP(self,packet,port):
        tcp_pk = tcp()
        tcp_pk.SYN = True
        tcp_pk.srcport=6633
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
        ip_pk.srcip=IPAddr('10.0.0.110')
        ip_pk.dstip=packet.payload.protosrc
        ip_pk.protocol=6
        ip_pk.set_payload(tcp_pk)
        ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
        ip_pk.csum=0
            
        ether_pk = ethernet()
        ether_pk.set_payload(ip_pk)
        ether_pk.src=EthAddr('00:00:00:00:00:09')
        ether_pk.dst = packet.src
        ether_pk.type= ethernet.IP_TYPE
            
        print "SEND SYN PARA : ",ip_pk.dstip
        self._send_packet(ether_pk.pack(),port)





def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Controlador(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
