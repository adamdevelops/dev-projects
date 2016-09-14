import os
import re
from string import letters
import random
import hashlib
import hmac
import jinja2
import webapp2
from users import *
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#Secret Salt
SECRET = 'imsosecret'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

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

#Database model for the blog posts
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    author = db.StringProperty()
    author_uid = db.StringProperty()
    likes = db.IntegerProperty(default = 0)
    post_id = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comment(db.Model):
    content = db.TextProperty(required=True)
    post_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty()
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c = self)

class CommentSection(BlogHandler):
    def get(self, post_id):
        posts = Post.all().order('-created')
        self.render('permalink.html', posts = posts, username = self.user)

    def post(self):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)



class BlogFront(BlogHandler):
    '''Blog Front class is the front page where all the blog posts made by
    users is posted.'''
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts = posts, username = self.user)

class PostPage(BlogHandler):
    '''Post Page class used to show the individual post the user
    submitted to the blog. Along with comments on the post by other users.'''
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = %s ORDER BY created DESC" % int(post_id))
        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, post_id = int(post_id), comments = comments, username = self.user)

    def post(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comment = self.request.get('comment')

        c = Comment(
                parent = blog_key(),
                comment = comment,
                post_id = int(post_id),
                author = self.user
                )
        c.put()
        self.redirect('/blog/%s' % str(post.key().id()))

        
        
class EditPostPage(BlogHandler):
    '''EditPost Page is used to edit an existing blog post by
    its original author.'''
    def get(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("edit-post.html", post = post, username = self.user)

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        a = self.request.cookies.get('user_id')
        uid = check_secure_val(a)
        author = Users.by_id(int(uid))

        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("edit-post.html", subject=subject, content=content, error=error)

class DeletePostPage(BlogHandler):
    '''DeletePost Page is used to delete a user's blog posts from
    the Blog's database.'''
    def get(self):
        self.render("delete-post.html", username = self.user)

    def post(self):
        if not self.user:
            self.redirect('/blog')

        delete_confirm = self.request.get('delete_confirm')

        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        post.delete()
        self.redirect('/blog')
                          
class NewPost(BlogHandler):
    '''New Post class used to create a new blog post on the blog using a form
    that requires a subject and content.'''
    def get(self):
        if self.user:
            self.render("newpost.html", username = self.user)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        a = self.request.cookies.get('user_id')
        uid = check_secure_val(a)
        author = Users.by_id(int(uid))
        
        if subject and content:
            p = Post(
                parent = blog_key(),
                subject = subject,
                content = content,
                author = author,
                author_uid = str(uid),
                likes = 0)
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

           #('/blog/comment/?', Comment),  
        
app = webapp2.WSGIApplication([('/', MainPage),
                              ('/signup', Register),
                              ('/login', Login),
                               ('/logout', Logout),
                              ('/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit?', EditPostPage),
                               ('/blog/delete?', DeletePostPage),                                                          
                               ],
                              debug=True)
