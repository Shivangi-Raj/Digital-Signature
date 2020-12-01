import random
from hashlib import sha256
from egcd import egcd
import os,sys
import time
start_time = time.time()

# y^2= x^3 + ax + b where a=0 and b=7 which is the secp256k1 curve bitcoin uses

Pcurve = (2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1) # The proven prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Acurve = 0
Bcurve = 7 # These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve
# Pcurve = 2**255-19
# N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
# Acurve = -1 3
# Bcurve = (121665/121666)*Pcurve  ax^2 +y^2=1+bx^2y^2 2^255-19
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
GPoint = (Gx,Gy) # This is our generator point. Trillions of dif ones possible
INV_MULT=1
POINT_O=(0,0)

def generatePrivateKey():
    size=32
    result = os.urandom(size) 
    print("private key ",result)
    ans=int.from_bytes(result, byteorder=sys.byteorder)
    if ans > 115792089237316195423570985008687907852837564279074904382605163141518161494336:
        raise Exception("Private key generation not in range please retry")
    return ans
    # privateKeyArray = []
    # for i in range(0, 256):
    #     bit = random.randint(1,100)
    #     if bit > 50:
    #         bit = 1
    #     else:
    #         bit = 0
    #     privateKeyArray.append(str(bit))

    # privateKeyBinary = int(''.join(privateKeyArray))
    # privateKeyDecimal = int(str(privateKeyBinary), 2)
    # privateKeyHex = hex(privateKeyDecimal)




    # # print("Private Key Binary: " + str(privateKeyBinary))
    # # print("Private Key Decimal: " + str(privateKeyDecimal))
    # print("Private Key Hex: " + str(privateKeyHex))

    # return int(privateKeyHex, 16)

def modinv(a,n=Pcurve): #Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = high//low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(a,b): #
    LamAdd = ((b[1]-a[1]) * modinv(b[0]-a[0],Pcurve)) % Pcurve # lambda = (Yq -Yp)/(Xq - Xp) where q and p are the point to be added
    x = (LamAdd*LamAdd-a[0]-b[0]) % Pcurve # Xr = lambda^2 - Xp - Xq where r is the resultant point
    y = (LamAdd*(a[0]-x)-a[1]) % Pcurve # Yr = lambda(Xp -Xr) - Yp where r is the resultant point
    return (x,y)

def ECdouble(a): # This is called point doubling, also invented for EC.
    Lam = ((3*a[0]*a[0]+Acurve) * modinv((2*a[1]),Pcurve)) % Pcurve # Lambda = (3Xp^2 + a)/2Yp
    x = (Lam*Lam-2*a[0]) % Pcurve # lambda^2 - 2Xp = Xr
    y = (Lam*(a[0]-x)-a[1]) % Pcurve # lambda(Xp - Xr) - Yp = Yr
    return (x,y)

def EccMultiply(GenPoint,ScalarHex): #Double & add. Not true multiplication
    # print("in ECCmultiple")
    if ScalarHex == 0 or ScalarHex >= N:
        raise Exception("Invalid Scalar/Private Key")
    scalarBin = str(bin(ScalarHex))[2:]
    Q = GenPoint
    # print("ndjs Q : ",Q)
    for i in range (1, len(scalarBin)): # This is invented EC multiplication.
        Q = ECdouble(Q) # print "DUB", Q[0]; print
        if scalarBin[i] == "1":
            Q = ECadd(Q,GenPoint) # print "ADD", Q[0]; print

    # print(Q)
    return Q

def generatePublicKey(privateKey):
    publicKey = EccMultiply(GPoint, privateKey)
    print("\n")
    print("******* Public Key Generation *********")
    print("the private key:" + str(privateKey))
    print("the uncompressed public key (not address): " + str(publicKey))
    # print("the uncompressed public key (HEX): " + "04" + "064" + str(publicKey[0]) + "064" + str(publicKey[1]))
    # print("the official Public Key - compressed:")
    if publicKey[1] % 2 == 1: # If the Y value for the Public Key is odd.
        print("03"+str(hex(publicKey[0])[2:]).zfill(64))
    else: # Or else, if the Y value is even.
        print("02"+str(hex(publicKey[0])[2:]).zfill(64))
    return publicKey



def digital_signature(message,n,GPoint,Acurve,Pcurve,priv_key,pub_key):
    r,s = 0,0
    while r == 0 or s == 0:
        k = random.randint(1,n-1) # 0x37D7CA00D2C7B0E5E412AC03BD44BA837FDD5B28CD3B0021
        x,y = EccMultiply(GPoint,k)
        r = x % n
        t = egcd(k,n)[INV_MULT]%n
        assert (1 == (k*t)%n )
        
        s = (t*(message +priv_key*r))%n
        #print(s)
    return (r,s)



def signature(message,N,GPoint,Acurve,Pcurve,priv_key,pub_key):
    print('*'*80)
    signature = digital_signature(message,N,GPoint,Acurve,Pcurve,priv_key,pub_key)
    return signature




def digital_verification(signature,message,n,Gpoint,Acurve,Pcurve,priv_key,pub_key):
    hash_message = int(sha256(message.encode("ascii")).hexdigest(),16)
    inverse_s= egcd(signature[1],n)[INV_MULT]%n

    assert (1 == (inverse_s * signature[1]) %n)
    
    u1,u2 = (hash_message*inverse_s)%n, (signature[0]*inverse_s)%n
    # X = u1*G + u2*Q, where Q is the public key
    pointX = ECadd(EccMultiply(Gpoint,u1),EccMultiply(pub_key,u2))
    print("PointX",pointX)
    is_valid = False
    # 0< s,r < n-1 and X != O
    if (pointX != POINT_O and 
            (0 < signature[1] < n-1 or 0 < signature[0] < n-1)):
        verification = pointX[0] %n
        is_valid = (verification == signature[0])

    return is_valid



def verification(signature,message,n,Gpoint,Acurve,Pcurve,priv_key,pub_key):
    valid = digital_verification(signature,message,n,GPoint,Acurve,Pcurve,priv_key,pub_key)
    print("valid",valid)
    assert valid




priv_key = generatePrivateKey()
pub_key= generatePublicKey(priv_key)
# print("\n")
print("The public Key : ",pub_key)
message="Hello this is the test message"
hash_message = int(sha256(message.encode('ascii')).hexdigest(),16)
print("message : ",message)
print("SHA message : ",hash_message)

digSign=signature(hash_message,N,GPoint,Acurve,Pcurve,priv_key,pub_key)   #edward curve 
print("The Digital Signature",digSign)
verification(digSign,message,N,GPoint,Acurve,Pcurve,priv_key,pub_key)
print("--- %s seconds ---" % (time.time() - start_time))
# print("time to run the program",current_time2-current_time1)


