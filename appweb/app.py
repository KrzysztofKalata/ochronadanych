from flask import Flask,request, make_response, render_template, session, flash, url_for, g
from flask_session import Session
from dotenv import load_dotenv
from os import getenv
from bcrypt import hashpw, checkpw, gensalt
import datetime
from jwt import encode, decode, InvalidTokenError
from redis import StrictRedis, Redis
import uuid
import jwt
import math
import time
from flask_sqlalchemy import SQLAlchemy

load_dotenv()
REDIS_HOST = getenv('REDIS_HOST')
REDIS_PASS = getenv('REDIS_PASS')
db = Redis(host='redis', port=6379, db=0)
SESSION_TYPE = "redis"
SESSION_REDIS = db
JWT_SECRET = getenv('JWT_SECRET')
app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")
app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite3'
app.config ['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
deactivationEndTime = time.time()
ses = Session(app)

login_counter = 0


# CONFIGURATION
database = SQLAlchemy(app)

class ipAddresses(database.Model):
    id = database.Column(database.Integer, primary_key = True)
    username = database.Column(database.String(50))
    ipAddress = database.Column(database.String(50))  

    def __init__(self, username, ipAddress):
        self.username = username
        self.ipAddress = ipAddress


class notes(database.Model):
    id = database.Column(database.Integer, primary_key = True)
    content = database.Column(database.String(1000))
    noteType = database.Column(database.String(10))
    owner = database.Column(database.String(100))
    sharedWith = database.Column(database.String(100))
    password = database.Column(database.String(500))
    title = database.Column(database.String(500))
    
    def __init__(self, content, noteType, owner, sharedWith, password, title):
        self.content = content
        self.noteType = noteType
        self.owner = owner
        self.sharedWith = sharedWith
        self.password = password
        self.title = title


    
def entropy(string):
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    entropy = entropy * -1
    return entropy


def get_profile_informations():
    profile_informations = {
        "login" : g.user,
    }
    return profile_informations

def list_to_string(lista):
    final_string = ''
    if len(lista) != 0:
        for element in lista:
            final_string += str(element)
            final_string += ','
        final_string = final_string[:-1]
    return final_string

@app.before_request
def get_logged_username():
    g.user = session.get('username')

def redirect(location):
    response = make_response("",301)
    response.headers["Location"] = location
    return response

def is_user(username):
    return db.hexists(f"user:{username}", "password")

def save_user(username, password):
    password = password.encode('utf-8')
    db.hset(f"user:{username}", "password", hashpw(password,gensalt(16)))
    return True

def verify_user(username, password):
    db_password = db.hget(f"user:{username}", "password")
    password = password.encode()

    if not db_password:
        return False
    if checkpw(password,db_password):
        return True
    return False

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods =['GET'])
def register_form():
    return render_template("register.html")

@app.route('/register', methods =['POST'])
def register():
    username = request.form.get("login")
    if not username:
        flash("Brak loginu")

    password = request.form.get("password")
    if not password:
        flash("Brak hasla")
        return redirect(url_for("register_form"))

    confirmPassword = request.form.get("confirmPassword")
    if confirmPassword != password:
        flash("Hasla nie sa zgodne")
        return redirect(url_for("register_form"))

    if entropy(password) < 3:
        flash("Entropia hasla jest za niska")
        return redirect(url_for("register_form"))

    if username and password:
        if is_user(username):
            flash("Uzytkownik jest juz zarejestrowany")
            return redirect(url_for("register_form"))

        try_save = save_user(username,password)
        try_save = True
        if not try_save:
            flash("Blad przy rejestracji")
            return redirect(url_for("register_form"))
    
    return redirect(url_for("login_form"))

@app.route('/login', methods = ['GET'])
def login_form():
    return render_template("login.html")

@app.route('/login', methods = ['POST'])
def login():
    global login_counter
    global deactivationEndTime

    if deactivationEndTime > time.time():
        flash('Przerwa ciagle trwa')
        return redirect(url_for("login"))

    if login_counter == 5:
        flash('Pora na przerwe')
        login_counter = 0
        deactivationEndTime = time.time() + 60
        return redirect(url_for("login"))

    username = request.form.get("login")
    password = request.form.get("password")
    time.sleep(1)
    # honeypots
    honeypotUsername = str(username).lower()
    if honeypotUsername == 'admin' or honeypotUsername == 'admin1' or honeypotUsername == 'developer':
        return redirect(url_for("admin_panel"))

    if not username or not password:
        flash("Brak loginu lub hasla")
        return redirect(url_for("login_form"))
    if not verify_user(username, password):
        flash("Bledny login lub haslo")
        login_counter += 1
        return redirect(url_for("login_form"))    
    login_counter = 0
    ip_address = request.remote_addr
    addresses = ipAddresses.query.filter_by(username = username, ipAddress = ip_address).all()
    
    if not addresses:
        address = ipAddresses(username = username, ipAddress = ip_address)
        database.session.add(address)
        database.session.commit()

    flash(f"Witaj {username}!")
    session['username'] = username
    session[username] = "Logged-at: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print('DO KONCA LOGINU')
    return redirect(url_for('profile_form'))

@app.route('/logout', methods = ["POST"])
def logout():
    cookie = request.cookies.get('session')
    if cookie:
        delete_success = db.delete('session:'+ cookie)
        if delete_success == 0:
            flash('Podczas wylogowywania wystapil blad')
    session.clear()
    g.user = None

    flash('Pomyslnie wylogowano!')
    return redirect(url_for('login_form'))

@app.route('/publicnotes', methods = ["GET"])
def public_notes():
    if g.user is None:
        return 'Not authorized',401

    public_notes = notes.query.filter_by(noteType = 'public').all()

    return render_template("publicnotes.html", public_notes = public_notes)

@app.route('/publicnotes', methods = ["POST"])
def public_notes_create():
    if g.user is None:
        return 'Not authorized',401

    content = request.form.get("content")
    title = request.form.get("title")
    note = notes(content = content, noteType = 'public',owner = g.user, sharedWith = '',password = '', title = title)
    database.session.add(note)
    try:
        database.session.commit()
    except:
        flash('Tytul musi byc unikalny na przestrzeni aplikacji, moze ktos ma juz taka notatke, sprobuj inny!')
        return redirect(url_for('public_notes'))

    return redirect(url_for('public_notes'))

    
@app.route('/sharednotes', methods = ["GET"])
def shared_notes():
    if g.user is None:
        return 'Not authorized',401
    
    shared_notes = notes.query.filter_by(noteType = 'shared', sharedWith = g.user).all()

    return render_template("sharednotes.html", shared_notes = shared_notes)

@app.route('/sharednotes', methods = ["POST"])
def shared_notes_create():
    if g.user is None:
        return 'Not authorized',401

    content = request.form.get("content")
    sharedWith = request.form.get('sharedWith')
    title = request.form.get('title')

    note = notes(content = content, noteType = 'shared',owner = g.user, sharedWith = sharedWith, password = '', title = title)
    
    database.session.add(note)

    try:
        database.session.commit()
    except:
        flash('Tytul musi byc unikalny na przestrzeni aplikacji, moze ktos ma juz taka notatke, sprobuj inny!')
        return redirect(url_for('shared_notes'))

    return redirect(url_for('shared_notes'))

@app.route('/privatenotes', methods = ["GET"])
def private_notes():
    if g.user is None:
        return 'Not authorized',401

    private_notes = notes.query.filter_by(owner = g.user, noteType = 'private').all()
    public_notes = notes.query.filter_by(owner = g.user, noteType = 'public').all()
    shared_notes = notes.query.filter_by(owner = g.user, noteType = 'shared').all()

    all_notes = private_notes + public_notes + shared_notes

    return render_template("privatenotes.html", all_notes = all_notes)

@app.route('/privatenotes', methods = ["POST"])
def private_notes_create():
    if g.user is None:
        return 'Not authorized',401

    content = request.form.get("content")
    title = request.form.get("title")
    note = notes(content = content, noteType = 'private', owner = g.user, sharedWith = '', password = '',title = title)
    database.session.add(note)
    try:
        database.session.commit()
    except:
        flash('Tytul musi byc unikalny na przestrzeni aplikacji, moze ktos ma juz taka notatke, sprobuj inny!')
        return redirect(url_for('private_notes'))

    return redirect(url_for('private_notes'))


@app.route('/privatenotessecure', methods = ["GET"])
def private_notes_secure():
    if g.user is None:
        return 'Not authorized',401

    private_notes = notes.query.filter_by(owner = g.user, noteType = 'secure').all()

    return render_template("privatenotessecure.html", private_notes = private_notes)

@app.route('/privatenotessecure', methods = ["POST"])
def private_notes_secure_create():
    if g.user is None:
        return 'Not authorized',401

    content = request.form.get("content")
    password = request.form.get('password')
    title = request.form.get('title')
    password = password.encode('utf-8')
    note = notes(content = content, noteType = 'secure',owner = g.user, password = hashpw(password, gensalt(16)), sharedWith = '', title = title)
    database.session.add(note)
    try:
        database.session.commit()
    except:
        flash('Tytul musi byc unikalny na przestrzeni aplikacji, moze ktos ma juz taka notatke, sprobuj inny!')
        return redirect(url_for('private_notes_secure'))
    
    return redirect(url_for('private_notes_secure'))

@app.route('/securenote', methods = ["POST"])
def secure_note():
    if g.user is None:
        return 'Not authorized',401

    password = request.form.get('password')
    title = request.form.get('title')
    username = g.user
    password = password.encode('utf-8')
    secure_note = notes.query.filter_by(owner = g.user,title = title).all()

    if not secure_note:
        flash('Błedny tytul lub hasło')
        return redirect(url_for('private_notes_secure'))
    
    note = secure_note[0]

    if checkpw(password, note.password):
        return render_template("securenote.html", secure_note = note)
    else:
        flash('Błedny tytul lub hasło')
        return redirect(url_for('private_notes_secure'))

@app.route('/profile', methods = ['GET'])
def profile_form():
    if g.user is None:
        return 'Not authorized',401
    profile_informations = get_profile_informations()

    addresses = ipAddresses.query.filter_by(username = g.user).all()
    return render_template('profile.html', profile_informations=profile_informations, addresses = addresses)

@app.route('/changepassword', methods = ['POST'])
def changepassword():
    if g.user is None:
        return 'Not authorized',401
    time.sleep(1)

    oldpassword = request.form.get("oldpassword")
    username = g.user
    if not verify_user(username, oldpassword):
        flash("Bledne haslo")
        return redirect(url_for("profile_form"))

    password = request.form.get("password")
    if not password:
        flash("Brak hasla")
        return redirect(url_for("profile_form"))

    confirmPassword = request.form.get("confirmPassword")
    if confirmPassword != password:
        flash("Hasla nie sa zgodne")
        return redirect(url_for("profile_form"))

    if entropy(password) < 3:
        flash("Entropia hasla jest za niska")
        return redirect(url_for("profile_form"))

    password = password.encode('utf-8')
    db.hset(f"user:{username}", "password", hashpw(password,gensalt(16)))
    flash('Haslo zostalo zmienione')
    return redirect(url_for("profile_form"))

@app.route('/admin/panel', methods = ['GET'])
def admin_panel():
    return render_template('admin.html')

if __name__ == '__main__':
    app.run()