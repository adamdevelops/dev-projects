import os
import re
from string import letters
import random
import hashlib
import hmac
import jinja2
import webapp2

from main import *
from google.appengine.ext import db

#Secret Salt
SECRET = 'imsosecret'

##### blog stuff  #####
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Cookie Hashing Alogirithm
def make_secure_val(s):
    return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

#Valid Input Field Algorithm
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

def existing_user(username):
    return username and Users.by_name(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


##### Password Hashing Algorithm
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


#Key created to have the option of users split into groups
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#Database model functions and user objects
class Users(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    
    @classmethod
    def by_id(cls, uid):
        u = Users.get_by_id(uid, parent = users_key())
        return u.name
    
    @classmethod
    def by_name(cls, name):
        #user = db.GqlQuery("SELECT * FROM Users WHERE user = :1", username)
        u = Users.all().filter('name =', name).get()
        return u
    
    @classmethod
    def register(cls, username, password, email = None):
        pw_hash = make_pw_hash(username, password)
        return cls(parent = users_key(),
                   name = username,
                    pw_hash = pw_hash,
                    email = email)    
    
    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u and valid_pw(username, password, u.pw_hash):
            return u

    def newpass(cls, username, password):
        return
        
