#import multiprocessing as mp
#from multiprocessing import pool
from decimal import Decimal, localcontext
import math

#x^y = e^(y ln x) O iverso de pow(x,y)

def recomputarMensagem(segredoAut, b, p):
    #b = float(b)
    #p = float(p)
    #segredoAut = float(segredoAut)

    mensagem = pow(b,segredoAut, p)

    #mensagem = (pow(b,segredoAut)%p)
    #a = segredoAut*math.log(b)
    #mensagem = pow(math.e,a)%p
    return mensagem

