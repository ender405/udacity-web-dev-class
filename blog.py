import os
import re
from string import letters
import time
import webapp2
import jinja2
import logging

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


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

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
            self.redirect('/unit2/welcome?username=' + username)

class Welcome(BaseHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

class Post(db.Model):   
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

#create a sample post
# p = Post()
# p.subject = "Sample subject"
# p.content = "This is my text"
# p.put()


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
                               ('/unit2/signup', Signup),
                               ('/unit2/welcome', Welcome),
                               ('/unit3/blog', Blog),
                               ('/unit3/blog/newpost', NewPost),
                               ('/unit3/blog/(\d+)', DisplayPost)],
                              debug=True)
