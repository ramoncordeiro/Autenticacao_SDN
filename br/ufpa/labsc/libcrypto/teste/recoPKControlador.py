def recoverPk(rec1,rec2,rec3,q):
    rec = (rec1+rec2+rec3)%q
    return rec


#q = 23
#print (recoverPk(10,12,50,q))
