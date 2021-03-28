from flask import Flask,render_template

app=Flask(__name__)

@app.route('/')
def home():
    return render_template('entry.html')

@app.route('/register')
def register():
    return render_template('register.html')
    
@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/generation')
def generation():
    return render_template('generation.html')

@app.route('/verification')
def verification():
    return render_template('verification.html')
if __name__=="__main__":
    app.run(debug=True,port=3000)