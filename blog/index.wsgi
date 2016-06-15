# -*- coding:utf-8 -*-
import os
import sae

sae.add_vendor_dir('vendor')
import webapp2
import cgi
import string
import re
import jinja2
import sae.kvdb
kv = sae.kvdb.Client()
import datetime

def escape_html(s):
    return cgi.escape(s,quote="True")

import json

template_dir = os.path.join(os.path.dirname(__file__), "templates")

jinja2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),autoescape=True)



def datetime_filter(t):
    delta = int(time.time() - t)
    if delta < 60:
        return u'1分钟前'
    if delta < 3600:
        return u'%s分钟前' % (delta // 60)
    if delta < 86400:
        return u'%s小时前' % (delta // 3600)
    if delta < 604800:
        return u'%s天前' % (delta // 86400)
    dt = datetime.fromtimestamp(t)
    return u'%s年%s月%s日' % (dt.year, dt.month, dt.day)



jinja2_env.filters['datetime'] = datetime_filter

def render_str(template, **params):
    t = jinja2_env.get_template(template)
    return t.render(params)





import time, uuid
from transwarp.db import next_id
from transwarp.orm import Model, StringField, BooleanField, FloatField, TextField



class User(Model):
    __table__ = 'users'

    id = StringField(primary_key=True, default=next_id, ddl='varchar(50)')
    email = StringField(updatable=False, ddl='varchar(50)',nullable=True)
    password = StringField(ddl='varchar(50)')
    admin = BooleanField()
    name = StringField(ddl='varchar(50)')
    image = StringField(ddl='varchar(500)')
    created_at = FloatField(updatable=False, default=time.time)

    @classmethod
    def by_id(cls,uid):
        return User.get(uid)

    @classmethod
    def by_name(cls,name):
        #u=User.all().filter('username=',name).get()
        u=User.find_by("where name=?",name)
        #u=db.GqlQuery("select * from User where username='%s'"%name)
        if u:
            return u[0]

    @classmethod
    def register(cls,name,pw,email=None):
        pw_hash=make_pw_hash(name,pw)
        return User(name=name,password=pw_hash,email=email)  #only create it not store it!

    @classmethod
    def login(cls,name,pw):
        u=cls.by_name(name)
        if u and valid_pw(name,pw,u.password):
            return u



class Blog(Model):
    __table__ = 'blogs'

    id = StringField(primary_key=True, default=next_id, ddl='varchar(50)')
    user_id = StringField(updatable=False, ddl='varchar(50)')
    user_name = StringField(ddl='varchar(50)')
    user_image = StringField(ddl='varchar(500)')
    name = StringField(ddl='varchar(50)')
    summary = StringField(ddl='varchar(200)')
    content = TextField()
    created_at = FloatField(updatable=False, default=time.time)


    def render(self):
        self._render_text=self.content.replace('\n','<br>') #without this replace .all the outcome will in one line.
        return render_str("blogpage.html",p=self)


    def render_json(self):
        blog={"title":self.name,"content":self.content,"user_id":str(self.user_id),"summary":self.summary,"created_at":str(self.created_at)  }
        # blog={"title":self.title,"content":self.content,"created":self.created,"email":self.email,"last_modified":self.last_modified}
        return json.dumps(blog)

class Comment(Model):
    __table__ = 'comments'

    id = StringField(primary_key=True, default=next_id, ddl='varchar(50)')
    blog_id = StringField(updatable=False, ddl='varchar(50)')
    user_id = StringField(updatable=False, ddl='varchar(50)')
    user_name = StringField(ddl='varchar(50)')
    user_image = StringField(ddl='varchar(500)')
    content = TextField()
    created_at = FloatField(updatable=False, default=time.time)



'''
class Blog(db.Model):
    title=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    email=db.StringProperty()
    last_modified=db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text=self.content.replace('\n','<br>') #without this replace .all the outcome will in one line.

        return render_str("blogpage.html",p=self)


    def render_json(self):
        blog={"title":self.title,"content":self.content,"created":str(self.created),"email":self.email,"last_modified":str(self.last_modified)  }
        # blog={"title":self.title,"content":self.content,"created":self.created,"email":self.email,"last_modified":self.last_modified}
        return json.dumps(blog)




class User(db.Model):
    username=db.StringProperty(required=True)
    password=db.StringProperty(required=True)
    last_signin=db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls,uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls,name):
        #u=User.all().filter('username=',name).get()
        u=db.GqlQuery("select * from User where username='%s'"%name)
        if u:
            return u[0]

    @classmethod
    def register(cls,name,pw,email=None):
        pw_hash=make_pw_hash(name,pw)
        return User(username=name,password=pw_hash,email=email)  #only create it not store it!

    @classmethod
    def login(cls,name,pw):
        u=cls.by_name(name)
        if u and valid_pw(name,pw,u.password):
            return u

'''
from transwarp import db
db.create_engine('root', '123456', 'awesome')


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.write(*a,**kw)

    def render_str(self,template,**params):
        t=jinja2_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def set_secure_cookie(self,name,val):
        cookie_val=make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/'% (name,cookie_val)
        )

    def read_secure_cooke(self,name):
        cookie_val=self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self,user):
        self.set_secure_cookie('user_id',str(user.id))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/'
        )

    def initialize(self,*a,**kw):
        webapp2.RequestHandler.initialize(self,*a,**kw)
        uid =self.read_secure_cooke('user_id')
        #self.user= uid and User.by_id(int(uid))

class MainPage(Handler):
    def write_form(self,error=""):
        self.response.write()

    def get(self):
        #blogs=db.GqlQuery("select * from Blog order by created DESC")
        blogs=Blog.find_all()

        self.render("bloglist.html",blogs=blogs)

    def post(self):
        self.response.write("Thanks")


class Add_blog(Handler):
    def post(self):
        title=self.request.get("title")
        content=self.request.get("content")
        if title=="" or content=="":
            error="Subject and content,Please"
            self.render("add_blog.html",error=error)
        else:
            a=Blog(name=title,content=content)
            a.insert()

            self.redirect('/blog/%s' %str(a.id))

    def get(self):
        self.render("add_blog.html")


class BlogPage(Handler):
    def get(self,blog_id):
        #key=db.Key.from_path('Blog',int(blog_id))
        blog=Blog.find_by("where id=?",blog_id)
        #blog=db.get(key)
        if not blog:
            self.error(404)
            return
        self.render("perment_link.html",blog=blog[0])




def valid_username(username):
    USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)

def valid_password(password):
    PASSWORD_RE=re.compile(r".{3,20}$")
    return PASSWORD_RE.match(password)

def valid_email(email):
    # EMAIL_RE=re.compile(r"^[\S]+@[\S]+.[\S]+$]")
    EMAIL_RE=re.compile(r"^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$")

    return EMAIL_RE.match(email)


import hmac
import random
SECRET = 'imsosecret'


import string
import hashlib



def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(name, pw,salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    hash_value,salt=h.split(',')
    return h == make_pw_hash(name,pw,salt)


def hash_str(s):
    ###Your code here
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


class Signup_handler(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        error1=error2=error3=error4=""

        username=self.request.get("username")
        password=self.request.get("password")
        verify=self.request.get("verify")
        email=self.request.get("email")

        if not(valid_username(username)):
            error1="Not a valid Name!"
        if not (valid_password(password)):
            error2="Not a valid Password"
        if email!="":
            if not (valid_email(email)):
                error4="Not a valid Email"
        if password!=verify:
            error3="Don't Match"

        user=User.by_name(username)
        if user:
            error5="The Username has benn registered"


        if error1+error2+error3+error4+error5=="":
            user=User.register(username,password,email)
            user.insert()
            self.login(user)
            self.redirect("/welcome")
        else:
            self.render("signup.html",error=error1+error2+error3+error4+error5,username=username,email=email)



class Welcome_handler(Handler):
    def get(self):
        hash_str=self.request.cookies.get('user_id',None)
        if hash_str:
            user_id=check_secure_val(hash_str)
            if user_id:
                user=User.by_id(user_id)
                if user:
                    self.response.write("Weclome "+user.name)
                    return

        self.redirect("/signup")


class Login_handler(Handler):
    def get(self):
        self.render("login.html")
    def post(self):
        error1=error2=""
        username=self.request.get("username")
        password=self.request.get("password")
        u=User.login(username,password)
        if u:
            self.login(u)
            self.redirect("/welcome")
        else:
            self.render("login.html",error="Password Error:"+username+password)

class Logout_handler(Handler):
    def get(self):
        self.logout()

class blog_json_handler(Handler):

    def get_blog(self,blog_id):
        blog=Blog.find_by("where id=?",blog_id)
        return blog


    def get(self,blog_id):

        blog=Blog.find_by("where id=?",blog_id)
        if not blog:
            self.error(404)
            return

        self.write(blog[0].render_json())

class MainPage_json_handler(Handler):
    def get(self):
        blogs=db.GqlQuery("select * from Blog order by created DESC")
        self.write( json.dumps([{"title":blog.name,"content":blog.content,"created":str(blog.created),"email":blog.email,"last_modified":str(blog.last_modified)} for blog in blogs]))


class hello_world_handler(Handler):
    def get(self):
        self.render("hello.html")

app = webapp2.WSGIApplication([
    ('/blog/?', MainPage),
    ('/blog/newpost',Add_blog),
    ('/blog/([0-9a-zA-Z]+)',BlogPage),
    ('/signup/?',Signup_handler),
    ('/welcome/?',Welcome_handler),
    ('/login/?',Login_handler),
    ('/blog.json/([0-9a-zA-Z]+)',blog_json_handler),
    ('/blog.json/?', MainPage_json_handler),
    ('/hello/?', hello_world_handler),
    # ('/logout/?',Logout_handler),
], debug=True)

application = sae.create_wsgi_app(app)

