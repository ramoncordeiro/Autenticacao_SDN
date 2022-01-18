__author__ = 'leonardo'

'''
Esta classe adiciona metadados as chaves ElGamal e cifras ElGamal.

Autor: Leonardo da Costa
Versao: 0.1 - 27/05/2015
'''

class ElGamalWrappler:

    electionId = None
    desc = None

    def __init__(self):
        pass

    '''
    Getters and setters
    '''
    def getDesc(self):
        return self.desc

    def setDesc(self, desc):
        self.desc = desc

    def getElectionID(self):
        return self.electionId

    def setElectionID(self, elecId):
        self.electionId = elecId
