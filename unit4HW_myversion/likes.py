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

class Likes(db.model):
    likes = db.IntegerProperty()
