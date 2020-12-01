
from flask import Flask, request,jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import random
from hashlib import sha256
from egcd import egcd
import os,sys

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']='HELLOWORLD'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///keys.db'
debug=False
ALLOWED_HOST = ["*"]

db = SQLAlchemy(app)
res = app.test_client()


Pcurve = (2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1) # The proven prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
# N= 2**252 + 27742317777372353535851937790883648493
Acurve = 0 # equation y^2 -x^2= 1- (121665/121666)x^2y^2
Bcurve = 7 # These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve
# Pcurve = 2**255-19
# Acurve=-1
# Bcurve=-(121665/121666)*Pcurve
# N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
# Gx=15112221349535400772501151409588531511454012693041857206046113283949847762202
# Gy=46316835694926478169428394003475163141307993866256225615783033603165251855960
GPoint = (Gx,Gy) # This is our generator point. Trillions of dif ones possible
INV_MULT=1
POINT_O=(0,0)



class Keys(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(200),unique=True, nullable=False)
    # private_key = db.Column(db.String, unique=True)
    public_key1 = db.Column(db.String(500))
    public_key2 = db.Column(db.String(500))






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


def generatePrivateKey():
    size=32
    result = os.urandom(size) 
    print("private key ",result)
    ans=int.from_bytes(result, byteorder=sys.byteorder)
    if ans > 115792089237316195423570985008687907852837564279074904382605163141518161494336:
        raise Exception("Private key generation not in range please retry")
    return ans



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




def digital_signature(message,n,GPoint,Acurve,Pcurve,priv_key):
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



def digital_verification(signature,message,n,Gpoint,Acurve,Pcurve,pub_key):
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


#key
@app.route('/key',methods =['POST'])
def key_generation():
    data = request.get_json()
    name=data['name']
    priv_key = generatePrivateKey()
    public_key= generatePublicKey(priv_key)
    pub_key1=str(public_key[0])
    pub_key2=str(public_key[1])
    # pub_key=str(public_key)
    new_key=Keys(name=name,public_key1=pub_key1,public_key2=pub_key2)
    db.session.add(new_key)
    db.session.commit()
    # print(data)
    return str(priv_key)

#generation
@app.route('/signGenr',methods =['POST'])
def Signature_generation():
    data = request.get_json()
    print(data)
    priv_key=int(data['priv_key'])
    message=data['message']
    # priv_key
    hash_message = int(sha256(message.encode('ascii')).hexdigest(),16)
    signature = digital_signature(hash_message,N,GPoint,Acurve,Pcurve,priv_key)
    return str(signature)
    # return "HELLO WORLD"
    
#verification
@app.route('/abc',methods =['POST'])
def Signature_verification():
    data = request.get_json()
    message=data['message']
    name=data['name']
    sign=data['sign']
    sign=sign.replace('(',"")
    sign=sign.replace(')',"")
    key = Keys.query.filter_by(name=name).all()
    print("key : ",key)
    public_key1=""
    public_key2=""
    # info={}
    output=[]
    
    print("id",key[0].id)
    public_key1 = key[0].public_key1
    public_key2 = key[0].public_key2
    # print("private_key",key[0].private_key)
    print("name",key[0].name)
    public_key=(int(public_key1),int(public_key2))
    r,s=sign.split(",")
    r=int(r)
    s=int(s)
    si=(r,s)
    # print(sign,r,s)
    # sign=(42958471855759167256101858031408456208934463311051244987014250435534392885166,53727692170010798141792781237101722146585415632392609601038023147966175690362)
    valid = digital_verification(si,message,N,GPoint,Acurve,Pcurve,public_key)
    print("valid",valid)
    # assert valid
    # # print(data)
    return str(valid)
    return "good"

if __name__=="__main__":
    app.run(debug=True,port=3001)