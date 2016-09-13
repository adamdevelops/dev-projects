import os
import re
from string import letters
import random
import hashlib
import hmac
import jinja2
import webapp2

from main import BlogHandler
from users import *
from google.appengine.ext import db

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
