import os
import re
from string import letters
import time
import webapp2
import jinja2
import logging
from auth import make_salt, make_pw_hash, valid_pw, hash_str, make_secure_val, check_secure_val
from validation import valid_username, valid_password, valid_email

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

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
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        def unique_username(username):        
            q = User.all()
            for user in q:
                if user.name == username:
                    return False #then it is not a unique username
            return True


        if not unique_username(username):
            params['error_username'] = "That username already exists."
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

        if have_error:
            self.render('signup-form.html', **params)
        else:
            
            #create the salt and password hash with make_pw_hash
            hashed_pw = make_pw_hash(username, password, None)

            #create the User object w/ name and email and the salt and password hash
            u = User(name=username, email=email, salt=hashed_pw.split(",")[1], pw_hash=hashed_pw.split(",")[0])

            #save the new User object
            u.put()

            #pull his user id from the newly created object
            user_id = str(u.key().id())

            #feed it into make_secure_val to get the formatted cookie with a pipe in between the user_id
            secure_val = make_secure_val(user_id)

            #set the cookie with user_id | hashed string (will need to get the user_id for the page render from the cookie set in the WelcomeHandler)
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % secure_val)
            self.redirect('/unit3/blog/welcome')

class Login(BaseHandler):
    def get(self):
        self.render("login.html")

    def post(self):

        username = self.request.get('username')
        password = self.request.get('password')

        def username_exists(username):        
            q = User.all()
            for user in q:
                if user.name == username:
                    return user.key().id() #then it is in the database
            return False

        user_id = username_exists(username)

        if user_id == False:
            self.render("login.html", error_login="Not a valid login")
        else:
            user = User.get_by_id(user_id)
            if valid_pw(username, password, user.pw_hash + "," + user.salt):
                secure_val = make_secure_val(str(user_id))
                self.response.delete_cookie('user_id')
                self.response.set_cookie('user_id', secure_val, max_age=24*60*60, path='/')
                self.redirect('/unit3/blog/welcome')
            else:
                self.render("login.html", error_login="Not a valid login")

class Logout(BaseHandler):
    def get(self):
        self.render('logout.html')

    def post(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/unit3/blog/signup')

class Welcome(BaseHandler):
    def get(self):
        #username = self.request.get('username')   This is no longer relevant
        #get cookie and use to auth and find username
        cookie = self.request.cookies.get("user_id")

        if check_secure_val(cookie):
            user = User.get_by_id(int(cookie.split("|")[0]))
            username = user.name
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit3/blog/signup')

class Post(db.Model):   
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
    name = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    salt = db.StringProperty()
    pw_hash = db.StringProperty()
    pw_updated = db.DateTimeProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class Blog(BaseHandler):

    def render_front(self, subject="", content="", error=""):
       posts = Post.gql("ORDER BY created DESC LIMIT 10")
       self.render("blog_front.html", subject = subject, content = content, error = error, posts = posts)

    def get(self):
        self.render_front()

    def post(self):
        self.render_front()


class DisplayPost(BaseHandler):
    def get(self, post_id):
        post_id = int(self.request.path.replace('/unit3/blog/', ""))
        post = Post.get_by_id(post_id)
        subject = post.subject
        content = post.content
        created = post.created
        self.render("blog_display.html", subject=subject, content=content, created=created)


class NewPost(BaseHandler):

    def get(self):
        self.render("blog_post.html", subject="", content="", error="")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            p = Post(subject=subject, content=content)
            p.put()
            post_id = p.key().id()
            self.redirect('/unit3/blog/%s' % post_id)
        else:
            error = "You must include both a subject and content to submit a post!"
            self.render('blog_post.html', subject = subject, content = content, error = error)


app = webapp2.WSGIApplication([('/unit2/rot13', Rot13),
                               ('/unit3/blog/welcome', Welcome),
                               ('/unit3/blog', Blog),
                               ('/unit3/blog/newpost', NewPost),
                               ('/unit3/blog/(\d+)', DisplayPost),
                               ('/unit3/blog/login', Login),
                               ('/unit3/blog/logout', Logout),
                               ('/unit3/blog/signup', Signup)],
                              debug=True)
