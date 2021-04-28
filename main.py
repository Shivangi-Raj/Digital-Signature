# # AS simeple as possbile flask google oAuth 2.0
# from flask import Flask, redirect, url_for, session
# from authlib.integrations.flask_client import OAuth
# import os
# from datetime import timedelta

# # decorator for routes that should be accessible only by logged in users



# # App config
# app = Flask(__name__)
# # Session config
# app.secret_key ='bF1ZPJ6fA_NeRXJC_-7YrZ-Y'
# app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

# # oAuth Setup
# oauth = OAuth(app)
# google = oauth.register(
#     name='google',
#     client_id='762670119940-nncgfi9f3sjaqu49tss26ife6e3thbl0.apps.googleusercontent.com',
#     client_secret='bF1ZPJ6fA_NeRXJC_-7YrZ-Y',
#     access_token_url='https://accounts.google.com/o/oauth2/token',
#     access_token_params=None,
#     authorize_url='https://accounts.google.com/o/oauth2/auth',
#     authorize_params=None,
#     api_base_url='https://www.googleapis.com/oauth2/v1/',
#     userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
#     client_kwargs={'scope': 'openid email profile'},
# )


# @app.route('/')
# def hello_world():
#     email = dict(session)['profile']['email']
#     return f'Hello, you are logge in as {email}!'


# @app.route('/login')
# def login():
#     google = oauth.create_client('google')  # create the google oauth client
#     redirect_uri = url_for('authorize', _external=True)
#     return google.authorize_redirect(redirect_uri)


# @app.route('/authorize')
# def authorize():
#     google = oauth.create_client('google')  # create the google oauth client
#     token = google.authorize_access_token()  # Access token from google (needed to get user info)
#     resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
#     user_info = resp.json()
#     user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
#     # Here you use the profile/user data that you got and query your database find/register the user
#     # and set ur own data in the session not the profile from google
#     session['profile'] = user_info
#     session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
#     return redirect('/')


# @app.route('/logout')
# def logout():
#     for key in list(session.keys()):
#         session.pop(key)
#     return redirect('/')

# if __name__=="__main__":
#     app.run(debug=True,port=3000)



from flask import Flask,request,url_for,render_template
from flask_mail import Mail,Message
from random import *  
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)  
# mail = Mail(app)  

app.config["MAIL_SERVER"]='smtp.gmail.com'  
app.config["MAIL_PORT"] = 465      
app.config["MAIL_USERNAME"] = 'shivangiraj779@gmail.com'  
app.config['MAIL_PASSWORD'] = 'Shivu1999@123'  
app.config['MAIL_USE_TLS'] = False  
app.config['MAIL_USE_SSL'] = True  

mail = Mail(app)  
otp = randint(000000,999999)   

s = URLSafeTimedSerializer('Thisisasecret!!')

@app.route('/', methods=['GET','POST'])  
def index():
    if request.method=='GET':
        return render_template("homepage.html")  
    email=request.form['email']
    token=s.dumps(email,salt='email-confirmation')
    msg = Message('Confirm Email',sender = 'shivangiraj779@gmail.com', recipients = [email])
    link=url_for('confirm',token=token,_external=True)
    msg.body='The confirmation link is given here {}  '.format(link)
    mail.send(msg)
    return 'The email you entered is {} . The token generated is {}'.format(email,token)

@app.route('/confirm_email/<token>')
def confirm(token):
    try:
        email=s.loads(token,salt='email-confirmation',max_age=300)
    except SignatureExpired:
        return "The Token Expired"
    return "The token works"

# @app.route('/verify',methods = ["POST"])  
# def verify():
#     email = request.form["email"]
#     msg = Message('OTP',sender = 'username@gmail.com', recipients = [email])
#     msg.body = str(otp)
#     mail.send(msg)
#     return render_template('verify.html')  
# @app.route('/validate',methods=["POST"])   
# def validate():
#     user_otp = request.form['otp']
#     if otp == int(user_otp):
#         return "<h3> Email  verification is  successful </h3>"
#     return "<h3>failure, OTP does not match</h3>"   
if __name__ == '__main__':
    app.run(port=5000,debug = True)