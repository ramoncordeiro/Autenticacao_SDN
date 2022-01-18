class Autenticador(object):
    def __init__(self, id, secret):
        self_id = id
        self_secret = None

    def setId(self,id):
        self.id = id

    def getId(self):
        return self.id

    def setSecret(self,secret):
        (self.secret) = long(secret)

    def getsecret(self):
        return self.secret

    def recomputarSegredo(self,l):
        val = self.secret*l
        return val

    def recomputarMensagem(self,b,p):
        #print ("segredo autenticador: ",self.getsecret())
        #print ("B dentro da funcao: ", b)
        #print ("p dentro da funcao: ", p)
        mensagem = pow(b,self.getsecret(),p) #%p
        #print ("trecho mensagem computado autenticador: ", mensagem)
        return mensagem