
from flask import Flask, request,jsonify ,redirect,render_template,send_from_directory,url_for,session
#8888
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
#8888
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import pymongo 
import dns
import certifi

from datetime import datetime,date
import random
from hashlib import sha256
from egcd import egcd
import os,sys
import timeit
import time
# from bigchaindb_driver import BigchainDB
# from bigchaindb_driver.crypto import generate_keypair
from authlib.integrations.flask_client import OAuth
from datetime import timedelta
from random import *

app = Flask(__name__)
oauth = OAuth(app)
'''google=oauth.register(
    oauth.register(
    name='google',
    client_id='762670119940-nncgfi9f3sjaqu49tss26ife6e3thbl0.apps.googleusercontent.com',
    client_secret='bF1ZPJ6fA_NeRXJC_-7YrZ-Y',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)
)'''
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SECRET_KEY']='HELLOWORLD'
app.secret_key ='bF1ZPJ6fA_NeRXJC_-7YrZ-Y'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///keys.db'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
debug=False
ALLOWED_HOST = ["*"]

app.config["MAIL_SERVER"]='smtp.gmail.com'  
app.config["MAIL_PORT"] = 465      
app.config["MAIL_USERNAME"] = 'shivangiraj779@gmail.com'  
app.config['MAIL_PASSWORD'] = 'Shivu1999@123'  
app.config['MAIL_USE_TLS'] = False  
app.config['MAIL_USE_SSL'] = True  

mail = Mail(app) 
# client=MongoClient("mongodb+srv://shivangi_raj:shivangi_raj@cluster0.3vdqz.mongodb.net/Digital_Signature?retryWrites=true&w=majority")
# db1=client.get_database('Digital_Signature')
# records=db1.keys

client =pymongo.MongoClient("mongodb+srv://shivangi_raj:shivangi_raj@cluster0.3vdqz.mongodb.net", tlsCAFile=certifi.where())
db = client['DigitalSignature']
records=db['keys']
print(client.list_database_names())



otp=randint(000000,999999)

s = URLSafeTimedSerializer('Thisisasecret!!')

# bdb_root_url = 'https://localhost:3001'
# bdb = BigchainDB(bdb_root_url)
#





# db = SQLAlchemy(app)
# res = app.test_client()
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
user_details=["username","password"]
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




def digital_signature(message,n,GPoint,Acurve,Pcurve,priv_key,username):
    # key = Keys.query.filter_by(name=username).all()
    key = records.find_one({"name":username})

    public_key1=""
    public_key2=""
    print("key :",key,username)
    public_key1 = key['public_key1']
    public_key2 = key['public_key2']
    publicKey=(int(public_key1),int(public_key2))
    r = hashMessage(hashMessage(message) + message) % Pcurve
    R = EccMultiply(GPoint, r)
    h = hashMessage(R[0] + publicKey[0] + message) % Pcurve
    s = (r + h * priv_key)
    return (R,s)



def digital_verification(signature,message,n,Gpoint,Acurve,Pcurve,pub_key):
    int_message = hashMessage(message)
    print("The hash message ",int_message)
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

@app.route('/',methods=['GET','POST'])
def home():
    # sample_doc={"name":"Honey@gmail.com","password":"hello","publicKey1":"12345","publicKey2":"6789"}
    # records.insert_one(sample_doc)
    return render_template('index.html')

@app.route('/about',methods=['GET','POST'])
def about():
    return render_template('a.html')


@app.route('/register', methods=['POST','GET'])
def register():
    error=None
    if request.method=='POST':
        email=request.form['reg_name']
        print(email)
        msg=Message(subject='OTP',sender='shivangiraj779@gmail.com',recipients=[email])
        msg.body=str(otp)
        mail.send(msg)

        user_name=email
        password=request.form["reg_pass"]
        confirm_password=request.form["reg_cnfpass"]
        l=[user_name,password,confirm_password]
        print("in get")
        if records.find_one({"name":user_name})!=None:
            error="Username is already registered"
            return render_template('signup.html',error=error)
        if password!=confirm_password:
            error="password doesn't match"
            return render_template('signup.html',error=error)
        user_details[0]=user_name
        user_details[1]=password
        return render_template('verify.html')
    return render_template("signup.html")


@app.route('/validate',methods=['POST'])
def validate():
    user_otp=request.form['otp']
    priv_key = generatePrivateKey()
    public_key= generatePublicKey(priv_key)
    pub_key1=str(public_key[0])
    pub_key2=str(public_key[1])
    with open("files/private.txt",'w') as f:
        f.write(str(priv_key))
    new_key={"name":user_details[0],"password":user_details[1],"public_key1":pub_key1,"public_key2":pub_key2}
    records.insert_one(new_key)
    target = os.path.join(app_root, 'files')
    files=send_from_directory(directory=target,filename="private.txt",as_attachment=True)
    if otp==int(user_otp):
        return send_from_directory(directory=target,filename="private.txt",as_attachment=True)
    return "<h3>Please Try Again</h3>"

    
@app.route('/login',methods=['POST','GET'])
def login():
    error=None
    if request.method=="POST":
        user_name=request.form["log_name"]
        # password=request.form["log_pass"]
        key = records.find_one({"name":user_name})
        # print("keys :",key)
        if(key==None):
            error="Invalid username or this username is not yet registered"
            return render_template('login.html',error=error)
            print(error)   
        password= key['password']
        # print("key",key,type(password),password)        
        if request.form['log_pass'] != password:
            error = 'Invalid Password. Please try again.'
            return render_template('login.html',error=error)
            print(error)
        else:
            l=[user_name]
            uri=url_for('generation',l=l) # http://ip addrss/generation/
            # uri="http://127.0.0.1:3001/generation/"+str(l)
            print("uri",uri)
            return redirect(uri)
    else:
        print("in get")
        # if request.form['submit_btn']=='google_signIn':
        #     print("in submit button")
        #     google = oauth.create_client('google')  # create the google oauth client
        #     redirect_uri = url_for('authorize', _external=True)
        #     return google.authorize_redirect(redirect_uri)
        return render_template('login.html',error=error)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()
    user = oauth.google.userinfo()  
    session['profile'] = user_info
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return redirect('/')

@app.route("/logout")
def logout():
    # session['logged_in'] = False
    return home()

#key
@app.route('/genration/<l>',methods =['POST','GET'])
def generation(l):
    if request.method=="POST":
        print("in post")
        if request.form['uploadbutton']=='genr_submit':
            target = os.path.join(app_root, 'files')
            if not os.path.isdir(target):
                os.makedirs(target)
            # username=request.form['fname']
            st=l.replace("['","")
            st=st.replace("']","")
            username=st
            # print("The Username :",type(l),l)
            private_key=request.files['priv_key']
            file = request.files['message']             
            priv_key_name=private_key.filename or ''
            file_name = file.filename or ''
            destination = '/'.join([target, file_name])
            destination_priv='/'.join([target, priv_key_name])
            # print("destination",destination)
            file.save(destination)
            private_key.save(destination_priv)
            with open(destination, 'r') as f:
                message = f.read()
            with open(destination_priv, 'r') as f:
                private_key = f.read()
            priv_key=int(private_key)
            print(message,priv_key)
            # timestamp=str(time.time())
            today = date.today()
            # # dd/mm/YY
            d1 = today.strftime("%d/%m/%Y")
            d1=d1.replace("/","") #ddmmyyyy
            timestamp=str(int(time.time())) #10char
            message=message+d1+timestamp
            message_in_int=hashMessage(message)
            print("hashvalue",message_in_int,message)
            # generation
            signature = digital_signature(message_in_int,N,GPoint,a,Pcurve,priv_key,username)
            # signature=timestamp
            #
            sign=str(signature)+d1+timestamp
            target = os.path.join(app_root, 'files')
            with open("files/sign.txt",'w') as f:
                f.write(sign)
            print(target)
            print(type(send_from_directory(directory=target,filename="sign.txt")))
            return send_from_directory(directory=target,filename="sign.txt",as_attachment=True)
        elif request.form['uploadbutton']=='log_out':
            print("sign out clicked")
            return redirect(url_for("logout"))
        else:
            pass
    else:
        print("list passed :",l,type(l))
        l=l.replace("['","")
        l=l.replace("']","")
        ind=l.index('@')
        st=l[:ind]
        return render_template('Generation.html',l=st)


@app.route('/verification/', methods=['POST','GET'])
def verification():
    ans=None
    a=0
    print(a)
    target = os.path.join(app_root, 'files')
    if not os.path.isdir(target):
        os.makedirs(target)
    if request.method == 'POST':
        print("in post verification")
        name=request.form['vname']
        signature=request.files['sign']
        file = request.files['message']
        sign_name=signature.filename or ''
        file_name = file.filename or ''
        destination_sign='/'.join([target,sign_name])
        destination = '/'.join([target, file_name])
        print("destination",destination)
        file.save(destination)
        signature.save(destination_sign)
        print(file,file_name)
        with open(destination_sign,'r') as s:
            sign= s.read()
        with open(destination, 'r') as f:
            message = f.read()
        # print(message,name,sign)

        # Adding time stamp to my message file
        timestamp=sign[-18:]
        sign=sign[:-18]
        print("time stamp in verification",timestamp,sign)
        message=message+timestamp
        # print("signature",sign,sign_name)

        sign=sign.replace(' ','')
        sign=sign.replace("\n",'')
        sign=sign.replace('(',"")
        sign=sign.replace(')',"")
        sig_split=sign.split(",")
        sign=((sig_split[0],sig_split[1]),sig_split[2])
        # print("signature 1 : ",sign)
        key = records.find_one({"name":name})
        if(key==None):
            # error="Invalid username or this username is not yet registered"
            # return render_template('login.html',error=error)
            print("a===4")
            a=4
            return render_template('verification.html',a=a)
        if(len(sign)<310 and len(sign)>320):
            # ans="Dangrous Host(Invalid Digital Signature)"
            print("a=======3")
            a=3
            return render_template('verification.html',a=a)
        public_key1=""
        public_key2=""
        output=[]
        public_key1 = key['public_key1']
        public_key2 = key['public_key2']
        public_key=(int(public_key1),int(public_key2))
        r1=int(sign[0][0])
        r2=int(sign[0][1])
        R=(r1,r2)
        s=int(sign[1])
        si=(R,s)
        # print("si is perfect",R,s)
        valid = digital_verification(si,message,N,GPoint,a,Pcurve,public_key)
        print("valid",valid)
        # ans=str(valid)
        ans="Noth"
        if(valid==True):
            a=1
        else:
            a=2
        print(a)
    print("in get verification")
    return render_template('verification.html',a=a)


if __name__=="__main__":
    app.run(debug=True,port=3001)