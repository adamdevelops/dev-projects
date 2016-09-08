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

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

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
        self.user = uid and Users.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
    def get(self):
        self.write('You are at the Main Page. Used for debugging purposes'
                   '<br>Click on: <br><a href="/signup">/signup</a> to go to the signup page'
                   '<br> <a href="/login">/login </a> to go to the login page')

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
    logged = db.StringProperty()
    
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

##### blog stuff  #####

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#Database model for the blog posts
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

#Blog Front class is the front page where all the blog posts made by users is posted.
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

#Post Page class used to show the individual post the user submitted to the blog.
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)
        
#New Post class used to create a new blog post on the blog using a form
#that requires a subject and content.
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

##### end of blog stuff  #####


#Signup Class used to handle the signup page form by extracting the credentials
#of the user and giving feedback on whether those credentials are correct.
class Signup(BlogHandler):   
    def get(self):
        self.render("signup-form.html")
    def post(self):
        #Form Error variable
        have_error = False
        
        #New Users crendentials
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        #Error checking of the signup form data. Checks for
        #valid username, password, email, and if the user exists already.
        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if existing_user(self.username):
            params['error_username'] = "That username is already exists, select a different one."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
             
        #self.response.headers.add_header('Set-Cookie', 'user=%s' % str(self.username)) ---TEST CODE

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


#Register Class used to input the new user in the database
#and login them into the blog site.
class Register(Signup):
    def done(self):
        u = Users.register(self.username, self.password, self.email)
        u.put()

        self.login(u)        
        self.redirect('/blog')

#Login Class for users that have been registered already.
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = Users.login(username, password)

        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')
        
#Welcome Class used to display the welcome page to a new user.
class Welcome(BlogHandler):
    def get(self):
##        u = self.request.cookie.get('user_id')
##        uid = check_secure_value(u)
##        username = Users.by_id(str(uid))
##        self.render('welcome.html', username = username)

        if self.user:
            self.render('welcome.html', username = self.user)
        else:
            self.redirect('/signup')

class NewPassword(BlogHandler):
    def get(self):
        self.render('change-password-form.html')
    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')

        u = Users.login(self.username, self.password)

        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)
        
app = webapp2.WSGIApplication([('/', MainPage),
                              ('/signup', Register),
                              ('/login', Login),
                               ('/logout', Logout),
                              ('/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/changepass', NewPassword),
                               ],
                              debug=True)
