__author__ = 'leonardo'

import json

'''
Esta classe codifica um objeto em json.
Ela tambem decodifica uma string json em
um objeto de sua classe correspondente.

Autor: Leonardo da Costa
Versao: 0.1 - 05/08/2015
'''

class CodDecJson:

    def __init__(self):
        '''
        Construtor da classe.
        '''

        pass

    def serialize(self, object, customOperations = False):
        '''
        Codifica um objeto em json.

        :param object: o objeto a ser codificado
        :param customOperations: um valor booleano que indica se o objeto precisa executar um metodo chamado
                                 "jsonCustomOperationsSer" antes de serializar o json. Este metodo e' usado para
                                 customizar o objeto.
        :return: string json
        '''

        if customOperations:
            object.jsonCustomOperationsSer()

        return json.dumps(object.__dict__)

    def deserialize(self, jsonString, type, customOperations = False):
        '''
        Decodifica uma string json em seu tipo de objeto correspondente.

        :param jsonString: a string json
        :param type: o tipo de objeto usado para gerar a string json
        :param customOperations: um valor booleano que indica se o objeto precisa executar um metodo chamado
                                 "jsonCustomOperationsDes" depois de deserializar o json. Este metodo e' usado para
                                 customizar o objeto.
        :return: um objeto do tipo "type"
        '''

        object = type()
        object.__dict__ = json.loads(jsonString)

        if customOperations:
            object.jsonCustomOperationsDes()

        return object