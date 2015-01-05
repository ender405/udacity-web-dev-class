import os
import re
from string import letters
import time
import webapp2
import jinja2
import logging
import datetime
import json
from auth import make_salt, make_pw_hash, valid_pw, hash_str, make_secure_val, check_secure_val
from validation import valid_username, valid_password, valid_email

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    
    def render_str(self, template, **params):
        params['user'] = self.user_present()
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def request_params(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        return dict(username = username, 
                    password = password, 
                    verify = verify, 
                    email = email)

    def login(self, secure_val):
        self.response.delete_cookie('user_id')
        self.response.set_cookie('user_id', secure_val, max_age=24*60*60, path='/')
        self.redirect('/blog/welcome')

    def logout(self):
        self.response.delete_cookie('user_id')
        self.redirect('/blog/signup')

    def get_cookie(self):
        return self.request.cookies.get("user_id")

    def user_present(self):
        cookie = self.get_cookie()
        if cookie:
            if check_secure_val(cookie):
                return User.by_cookie(cookie)
        return None



class Rot13(BaseHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


class Signup(BaseHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        req = self.request_params()

        params = dict(username = req['username'],
                      email = req['email'])

        if not valid_username(req['username']):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(req['password']):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif req['password'] != req['verify']:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(req['email']):
            params['error_email'] = "That's not a valid email."
            have_error = True
        
        hashed_pw = make_pw_hash(req['username'], req['password'], None)
        u = User.register(req['username'], req['email'], hashed_pw.split(',')[1], hashed_pw.split(',')[0])
        
        if not u.unique_username(u.name):
            params['error_username'] = 'That username already exists.'
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u.put()
            secure_val = make_secure_val(str(u.key().id()))
            self.login(secure_val)

class Login(BaseHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        req = self.request_params()
        user = User.by_name(req['username'])

        if user == None:
            self.render("login.html", error_login="Not a valid login")
        else:
            if valid_pw(req['username'], req['password'], user.pw_hash + "," + user.salt):
                secure_val = make_secure_val(str(user.key().id()))
                self.login(secure_val)
            else:
                self.render("login.html", error_login="Not a valid login")

class Logout(BaseHandler):
    def get(self):
        self.render('logout.html')

    def post(self):
        cookie = self.get_cookie()

        if check_secure_val(cookie):
            self.logout()
        else:
            self.render('signup-form.html')


class Welcome(BaseHandler):
    def get(self):
        #username = self.request.get('username')   This is no longer relevant
        #get cookie and use to auth and find username
        cookie = self.get_cookie()
        if check_secure_val(cookie):
            username = User.by_cookie(cookie).name
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')

class Post(db.Model):   
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

class User(db.Model):
    name = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    salt = db.StringProperty()
    pw_hash = db.StringProperty()
    pw_updated = db.DateTimeProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        user = User.all().filter('name =', name).get()
        return user

    @classmethod
    def unique_username(cls, username):        
        user = User.by_name(username)
        if user:
            return False #then it is not a unique username
        return True

    @classmethod
    def by_cookie(cls, cookie):
        return User.by_id(int(cookie.split("|")[0]))

    @classmethod
    def register(cls, name, email, salt, pw_hash):
        return User(name=name, email=email, salt=salt, pw_hash=pw_hash)


def front_cache(update=False):
    key = 'front'
    if not memcache.get(key) or update:
        memcache.set(key, (Post.gql("ORDER BY created DESC LIMIT 10"), datetime.datetime.now()))
        return memcache.get(key)
    else:
        return memcache.get(key)

def post_cache(post_id, update=False):
    key = str(post_id)
    if not memcache.get(key) or update:
        memcache.set(key, (Post.by_id(post_id), datetime.datetime.now()))
        return memcache.get(key)
    else:
        return memcache.get(key)

class Blog(BaseHandler):

    def render_front(self, subject="", content="", error=""):
       key = "front"
       posts = front_cache()[0]
       db_query = front_cache()[1]
       time = (datetime.datetime.now() - db_query).seconds
       self.render("blog_front.html", subject = subject, content = content, error = error, posts = posts, time = "Queried " + str(time) + " seconds ago")

    def get(self):
        self.render_front()

class DisplayPost(BaseHandler):
    def get(self, post_id):
        post_id = int(self.request.path.replace('/blog/', ""))
        post_tuple = post_cache(post_id)
        post = post_tuple[0]
        subject = post.subject
        content = post.content
        created = post.created
        time = (datetime.datetime.now() - post_tuple[1]).seconds
        self.render("blog_display.html", subject=subject, content=content, created=created, time = "Queried " + str(time) + " seconds ago")


class NewPost(BaseHandler):

    def get(self):
        self.render("blog_post.html", subject="", content="", error="")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            p = Post(subject=subject, content=content)
            p.put()
            front_cache(True)
            post_id = p.key().id()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "You must include both a subject and content to submit a post!"
            self.render('blog_post.html', subject = subject, content = content, error = error)

class JsonMain(Blog):
    def get(self):
        posts = Post.all().order("-created").fetch(10)
        posts = [{"subject" : post.subject,"content" : post.content,"created" : post.created.isoformat()} for post in posts]
        self.response.headers['Content-Type'] = 'application/json'
        self.write(json.dumps(posts))


class JsonPerm(Blog):
    def get(self, post_id):
        post_id = int(self.request.path.replace('/blog/', "").replace('.json', ""))
        post = Post.by_id(post_id)
        post = [{"subject" : post.subject,"content" : post.content,"created" : post.created.isoformat()}]
        self.response.headers['Content-Type'] = 'application/json'
        self.write(json.dumps(post))

class Flush(BaseHandler):
    def get(self):
        r = memcache.flush_all()
        if r:
            self.redirect('/blog')
        else:
            self.error('404')


app = webapp2.WSGIApplication([('/unit2/rot13', Rot13),
    ('/blog/welcome', Welcome),
    ('/blog/?', Blog),
    ('/blog/newpost', NewPost),
    ('/blog/(\d+)', DisplayPost),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/signup', Signup),
    ('/blog/.json', JsonMain),
    ('/blog/(\d+).json', JsonPerm),
    ('/blog/flush', Flush)],
    debug=True)

# the parens in the path means it is passed in as a parameter to get and post requests