import webapp2
import jinja2
import hmac
import hashlib 
import os
import re
import random
import string
import json
import logging 
from string import letters
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = "SUSHRUSHA"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def hash_str_hmac(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s,hash_str_hmac(s))

def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)     

        
def make_salt():
    new_str = ""
    for i in range(0,5):
        rando  = random.choice(string.letters)
        new_str += rando
    return new_str

def make_pw_hash(name,pw,salt = None):
    if not salt:
        salt = make_salt()
    password = hashlib.sha256(name+pw+salt).hexdigest()
    return  salt + "," + password

def valid__pw(name,pw,h):
    item = h.split(",")
    return make_pw_hash(name, pw, item[0]) == h

def render_post(response, post):
    response.out.write('<b>' + post.title + '</b><br>')
    response.out.write(post.content)

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
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

    # checks id user is logged in everytime or not 
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class Blog(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    modified = db.DateProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', a = self)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        # similar to u = db.GqlQuery("SELECT * FROM User where name = name")
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid__pw(name, pw, u.pw_hash):
            return u

def storage(update = False):
    key = 'blog'
    contents = memcache.get(key)
    if update or contents is None:
        logging.error("Surabhya")
        contents = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 15")
        contents = list(contents)
        memcache.set(key, contents)
    return contents 

class BlogPage(Handler):

   def get(self):
        contents = storage()
        self.render("blogpage.html", contents = contents)

class AddBlog(Handler):
    def get(self):
        self.render("addblog.html")

    def post(self):
        title = self.request.get("title")
        content = self.request.get("content")

        if title and content:
            a = Blog(title = title, content = content)
            a.put()
            storage(True) 
        else:
            error = "Could you please submit both, the Title and the Content"
            self.render("addblog.html", title = title, content = content, error = error)

class PostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.render("singlepost.html",post=post)
            

class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
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

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError  
        
class WelcomePage(Handler):

    def get(self):
        if self.user:
            self.render("welcome.html", username = self.user.name)
        else:
            self.redirect('/blog/signup')

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/blog/welcome')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/welcome')   
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class BlogPageJson(Handler):
    
    def get(self):
         contents = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
         json_list = []
         for c in contents:
             dic = {}
             dic['title'] = c.title
             dic['content'] = c.content
             dic['created'] = "" + str(c.created)
             dic['modified'] = "" + str(c.modified)
             json_list.append(dic)
         x = json.dumps(json_list)
         self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
         self.write(x) 
    
class BlogJson(Handler):
    def get(self, blogid):
        key = db.Key.from_path('Blog', int(blogid))
        contents = db.get(key)
        if not contents:
            self.error(404)
            return
        else:
            json_list = []
            dic = {}
            dic['title'] = contents.title
            dic['content'] = contents.content
            dic['created'] = "" + str(contents.created)
            dic['modified'] = "" + str(contents.modified)
            json_list.append(dic)
            x = json.dumps(json_list)
            self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
            self.write(x) 
        

        
app = webapp2.WSGIApplication([('/', BlogPage),
                               ('/blog', BlogPage),
                               ('/blog/addblog', AddBlog),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/welcome', WelcomePage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/.json', BlogPageJson),
                               ('/([0-9]+).json', BlogJson),
                               ],
                              debug=True)
