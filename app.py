
from flask import Flask, request,jsonify ,redirect,render_template,send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from datetime import datetime
import random
from hashlib import sha256
from egcd import egcd
import os,sys
import timeit
# from bigchaindb_driver import BigchainDB


app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']='HELLOWORLD'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///keys.db'
debug=False
ALLOWED_HOST = ["*"]
bdb_root_url = 'https://localhost:3001'
# bdb = BigchainDB(bdb_root_url)
#


db = SQLAlchemy(app)
res = app.test_client()
app_root = os.path.dirname(os.path.abspath(__file__))

########### For kobalts curve, the specifications ################

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field


#--------------------------------------------------------------#--------------------------------------------------------------#--------------------------------------------------------------#--------------------------------------------------------------

############ For EDWARD CURVE (Ed25519) ###########################
# Equation = ax^2 +y^2 = 1+dx^2y^2 #
Pcurve = pow(2, 255) - 19
Gx=15112221349535400772501151409588531511454012693041857206046113283949847762202
Gy=46316835694926478169428394003475163141307993866256225615783033603165251855960
GPoint = (Gx,Gy) # This is our generator point. Trillions of dif ones possible
a = -1
# -x2 + y2 = 1 – (121665/121666) x2y2 (mod 2255 – 19)

def modinv(a,n=Pcurve): #Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = high//low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n
    
ddash = 121665 * modinv(121666, Pcurve) #ed25519 as the value would have been -ve because d is -ve so finding positive modulous for it
d=Pcurve-(ddash%Pcurve)


class Keys(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(200),unique=True, nullable=False)
    # private_key = db.Column(db.String, unique=True)
    public_key1 = db.Column(db.String(500))
    public_key2 = db.Column(db.String(500))



def textToInt(text):
    encoded_text = text.encode()
    hex_text = encoded_text.hex()
    int_text = int(hex_text, 16)
    return int_text


def ECadd(n1,n2): #
    # Beta = ((b[1]-a[1]) * modinv(b[0]-a[0],Pcurve)) % Pcurve # Beta = (Yq -Yp)/(Xq - Xp) where q and p are the point to be added
    # x3 = (Beta*Beta-a[0]-b[0]) % Pcurve # Xr = Beta^2 - Xp - Xq where r is the resultant point
    # y3 = (Beta*(a[0]-x3)-a[1]) % Pcurve # Yr = Beta(Xp -Xr) - Yp where r is the resultant point
    x1 = n1[0]
    y1 = n1[1]
    x2 = n2[0]
    y2 = n2[1]
    x3 = (((x1*y2 + y1*x2) % Pcurve) * modinv(1+d*x1*x2*y1*y2, Pcurve)) % Pcurve
    y31 = (y1*y2 - a*x1*x2) % Pcurve
    y32 = modinv(1- d*x1*x2*y1*y2, Pcurve)
    y3 = (y31*y32)% Pcurve
    return (x3,y3)


# No ECC Double in Edward Curve ########

# def ECdouble(a): # This is called point doubling, also invented for EC.
#     Beta = ((3*a[0]*a[0]+Acurve) * modinv((2*a[1]),Pcurve)) % Pcurve # Lambda = (3Xp^2 + a)/2Yp
#     x3 = (Beta*Beta-2*a[0]) % Pcurve # beta^2 - 2Xp = Xr
#     y3= (Beta*(a[0]-x3)-a[1]) % Pcurve # beta(Xp - Xr) - Yp = Yr
#     return (x3,y3)

def EccMultiply(GenPoint,ScalarInt): #Double & add. Not true multiplication
    # print("in ECCmultiple")
    if ScalarInt == 0 :
        raise Exception("Invalid Scalar/Private Key")
    scalarBin = str(bin(ScalarInt))[2:]
    R = GenPoint
    # print("ndjs Q : ",Q)
    for i in range (1, len(scalarBin)): # This is invented EC multiplication.
        R = ECadd(R,R) # print "DUB", Q[0]; print
        if scalarBin[i] == "1":
            R = ECadd(R,GenPoint) # print "ADD", Q[0]; print

    # print(Q)
    print("working ok EccMultiply 115")
    return R


def generatePrivateKey():
    size=32
    result = os.urandom(size) 
    print("private key ",result)
    ans=int.from_bytes(result, byteorder=sys.byteorder)
    if ans > 2**256:
        raise Exception("Private key generation not in range please retry")
    return ans



def generatePublicKey(privateKey):
    publicKey = EccMultiply(GPoint, privateKey)
    print("\n")
    print("******* Public Key Generation *********")
    print("the private key:" + str(privateKey))
    print("the uncompressed public key (not address): " + str(publicKey))
    if publicKey[1] % 2 == 1: # If the Y value for the Public Key is odd.
        print("03"+str(hex(publicKey[0])[2:]).zfill(64))
    else: # Or else, if the Y value is even.
        print("02"+str(hex(publicKey[0])[2:]).zfill(64))
    return publicKey

def hashMessage(message):
    hash_message = int(sha256(str(message).encode('ascii')).hexdigest(),16)
    return hash_message




def digital_signature(message,n,GPoint,Acurve,Pcurve,priv_key):
    publicKey= (7898651914271609667200961661227034323655772406619074699519311977312344259534,8727739791330194990567819163971370160537209299707121300169064837432917334113)
    # publicKey=(24649997625158719148197039178713781596844819968152314347662800023973838986324,29054514210612187021911206675018486354389550454524519643831189136130687914734)
    r = hashMessage(hashMessage(message) + message) % Pcurve
    R = EccMultiply(GPoint, r)
    h = hashMessage(R[0] + publicKey[0] + message) % Pcurve
    s = (r + h * priv_key)
    return (R,s)



def digital_verification(signature,message,n,Gpoint,Acurve,Pcurve,pub_key):
    int_message = textToInt(message)
    print("signature:   ",signature[0][0])
    h = hashMessage(signature[0][0] + pub_key[0] + int_message) % Pcurve
    print("line 174 success")
    P1 = EccMultiply(GPoint, signature[1])
    print("line 176 success")
    P2 = ECadd(signature[0], EccMultiply(pub_key, h))
    print("line 178 success")
    is_valid=False
    if P1==P2:
        print("line 181 success")
        is_valid=True


    return is_valid

#key
@app.route('/key',methods =['POST'])
def key_generation():
    start = timeit.default_timer()
    data = request.get_json()
    name=data['name']
    priv_key = generatePrivateKey()
    public_key= generatePublicKey(priv_key)
    pub_key1=str(public_key[0])
    pub_key2=str(public_key[1])
    with open("files/private.txt",'w') as f:
        f.write(str(priv_key))
    new_key=Keys(name=name,public_key1=pub_key1,public_key2=pub_key2)
    db.session.add(new_key)
    db.session.commit()
    target = os.path.join(app_root, 'files')
    stop = timeit.default_timer()
    print('Time: ', stop - start)
    return send_from_directory(directory=target,filename="private.txt",as_attachment=True)


#generation
@app.route('/signGenr',methods =['POST'])
def Signature_generation():
    target = os.path.join(app_root, 'files')
    if not os.path.isdir(target):
        os.makedirs(target)
    if request.method == 'POST':
        private_key=request.form['priv_key']
        priv_key=int(private_key)
        print(type(priv_key))
        file = request.files['message']
        # priv_key_name=private_key.filename or ''
        file_name = file.filename or ''
        destination = '/'.join([target, file_name])
        # destination_priv='/'.join([target, priv_key_name])
        print("destination",destination)
        file.save(destination)
        # private_key.save(destination_priv)
        print(file,file_name)
        with open(destination, 'r') as f:
            message = f.read()
        # with open(destination_priv, 'r') as f:
            # private_key = f.read()
    # priv_key=int(private_key)
    print(message)
    message_in_int=textToInt(message)
    signature = digital_signature(message_in_int,N,GPoint,a,Pcurve,priv_key)
    target = os.path.join(app_root, 'files')
    with open("files/sign.txt",'w') as f:
        f.write(str(signature))
    print(target)
    print(type(send_from_directory(directory=target,filename="sign.txt")))
    return send_from_directory(directory=target,filename="sign.txt",as_attachment=True)
    
#verification
@app.route('/abc',methods =['POST'])
def Signature_verification():
    target = os.path.join(app_root, 'files')
    if not os.path.isdir(target):
        os.makedirs(target)
    if request.method == 'POST':
        name=request.form['name']
        sign=request.form['sign']
        file = request.files['message']
        # sign_name=signature.filename or ''
        file_name = file.filename or ''
        # destination_sign='/'.join([target,sign_name])
        destination = '/'.join([target, file_name])
        print("destination",destination)
        file.save(destination)
        # signature.save(destination_sign)
        print(file,file_name)
        # with open(destination_sign,'r') as s:
            # sign= s.read()
        with open(destination, 'r') as f:
            message = f.read()
    print(message,name)
    # print("signature",sign,sign_name)
    sign=sign.replace(' ','')
    sign=sign.replace('(',"")
    sign=sign.replace(')',"")
    sig_split=sign.split(",")
    sign=((sig_split[0],sig_split[1]),sig_split[2])
    print("signature 1 : ",sign)
    key = Keys.query.filter_by(name=name).all()
    public_key1=""
    public_key2=""
    output=[]
    public_key1 = key[0].public_key1
    public_key2 = key[0].public_key2
    public_key=(int(public_key1),int(public_key2))
    r1=int(sign[0][0])
    r2=int(sign[0][1])
    R=(r1,r2)
    s=int(sign[1])
    si=(R,s)
    print("si is perfect",R,s)
    valid = digital_verification(si,message,N,GPoint,a,Pcurve,public_key)
    print("valid",valid)
    return str(valid)
    # # print(data)
    # return "True"

if __name__=="__main__":
    app.run(debug=True,port=3001)