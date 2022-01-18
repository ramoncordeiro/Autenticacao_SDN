def computeM(di,l0,dj,l1,dk,l2,c,p):
    da = pow(di,l0,p)
    db = pow(dj, l1,p)
    dc = pow(dk, l2,p)
    j = (da*db*dc)
    m = (pow(j,p-2,p)*c)%p
    return m

#print ("a mensagem e :", computeM(12,18,2,17,21,10,3,23))