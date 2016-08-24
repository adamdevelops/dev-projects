import os
import re
from string import letters
import random
import hashlib
import hmac
import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#Secret Salt
SECRET = 'imsosecret'

#Valid Input Field Algorithm
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
    

# Cookie Hashing Alogirithm
def make_secure_val(s):
    return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val 

#Blog Handler
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a,**kw)
        
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

##### user stuff
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

class Users(db.Model):
    user = db.StringProperty(required = True)
    user_id = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    logged = db.StringProperty(required = True)

    @classmethod
    def by_id(cls, uid):
        return Users.get_by_id()

    @classmethod
    def by_name(cls, username):
        user = GqlQuery("SELECT * FROM Users WHERE user = :1", username)
        u = user.get(username)
        return u
    @classmethod
    def register(cls, username, password, email):
        pw_hash = make_pw_hash(username, password)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)
    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u and valid_pw(username, password, u.pw_hash):
            return u

class MainPage(BlogHandler):
    def get(self):
        self.write("You are at the Main Page")

#Signup Page Handler
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")
    def post(self):
        self.response.headers['Content-Type'] = 'text/plain'
                         
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      password = self.password,
                      email = self.email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if Users.by_name(username) == username:
            params['error_username'] = "That username is used already, select a different one."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True
              
        self.response.headers.add_header('Set-Cookie', 'user=%s' % username)

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError



class Register(Signup):
    def done(self):
        u = Users.register(self.username, self.password, self.email)
        u.put()

        self.login(u)        
        self.redirect('/welcome')

#Welcome Page for signed in user Handler
class Welcome(BlogHandler):
    def get(self):
        self.render('welcome.html', username = self.username)
        

        
app = webapp2.WSGIApplication([('/', MainPage),
                              ('/signup', Register),
                              ('/welcome', Welcome),
                               ],
                              debug=True)
