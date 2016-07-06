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
from tools import *
from models import *

def escape_html(s):
    return cgi.escape(s,quote="True")

import json

template_dir = os.path.join(os.path.dirname(__file__), "templates")

jinja2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),autoescape=True)






jinja2_env.filters['datetime'] = datetime_filter

def render_str(template, **params):
    t = jinja2_env.get_template(template)
    return t.render(params)





from transwarp import db
db.create_engine('root', '123456', 'awesome')


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.write(*a,**kw)

    def render_str(self,template,**params):
        t=jinja2_env.get_template(template)
        params.setdefault("user",self.user)
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
        self.user= uid and User.by_id((uid))

class MainPage(Handler):
    def write_form(self,error=""):
        self.response.write()

    def get(self):
        #blogs=db.GqlQuery("select * from Blog order by created DESC")
        blogs=Blog.find_all()
        blogs.reverse()

        self.render("bloglist.html",blogs=blogs,user=self.user)

    def post(self):
        self.response.write("Thanks")


class Add_blog(Handler):
    def post(self):
        name=self.request.get("name")
        summary=self.request.get("summary")
        content=self.request.get("content")
        if name=="" or content=="":
            error="Subject and content,Please"
            self.render("add_blog.html",error=error)
        else:
            a=Blog(name=name,
                   summary=summary,
                   content=content)
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
        comments = Comment.find_by('where blog_id=? order by created_at desc limit 1000', blog_id)
        self.render("blogpage.html",p=blog[0],comments=comments)





class Signup_handler(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        error1=error2=error3=error4=""

        username=self.request.get("username")
        password=self.request.get("password")
        verify=self.request.get("verify")
        email=self.request.get("email")
        error5=""
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
        name=self.request.get("name").strip().lower()
        password=self.request.get("password")
        user=User.login(name,password)
        if user is None:
            raise APIError('auth:failed', 'name', 'Invalid name.')
        elif not valid_pw(name, password, user.password):
            raise APIError('auth:failed', 'password', 'Invalid password.')

        if user:
            self.login(user)
            self.redirect("/")
        else:
            # self.render("login.html",error="Password Error:"+email+password)
            user.password = '******'
            self.write(get_json(dict(user=user)))

class Logout_handler(Handler):
    def get(self):
        self.logout()
        # logging.warn(self.request.url)
        self.redirect("/")


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


class Manage_blogList_handler(Handler):
    def get(self):
        # logging.warn("test")
        return self.render("manage_bloglist.html",page_index=1)

from apis import *
import logging

@api
def get_json(kw):
    return kw



class api_get_blogs(Handler):
    @api
    def get_json(self,kw):
        return (kw)

    def get(self):
        format = self.request.get('format', '')
        index = self.request.get('page','1')
        # logging.warn("test")
        blogs, page = get_blog_by_page(int(index))
        # if format=='html':
        #     for blog in blogs:
        #         blog.content = markdown2.markdown(blog.content)
        # return dict(blogs=blogs, page=page)
        return self.write(self.get_json(dict(blogs=blogs, page=page)))


class api_blog_delete(Handler):

    def post(self,blog_id):
        blog=Blog.get(blog_id)
        if blog is  None:
            raise APIResourceNotFoundError('Blog')
        blog.delete()
        return self.write(get_json(dict(id=blog_id)))


class api_blog(Handler):

    def get(self,blog_id):
        blog=Blog.get(blog_id)
        if blog is  None:
            raise APIResourceNotFoundError('Blog')
        return self.write(get_json(dict(blog=blog)))

    def post(self,blog_id):
        # logging.warn(self.request)
        # blog=self.request.get("blog")
        name=self.request.get("blog[name]")
        summary=self.request.get("blog[summary]")
        content=self.request.get("blog[content]")
        # logging.warn("blog:"+blog+"name:"+name+" summary:"+summary)
        if not name:
            raise APIValueError('name', 'name cannot be empty.')
        if not summary:
            raise APIValueError('summary', 'summary cannot be empty.')
        if not content:
            raise APIValueError('content', 'content cannot be empty.')
        blog = Blog.get(blog_id)
        if blog is None:
            raise APIResourceNotFoundError('Blog')
        blog.name = name
        blog.summary = summary
        blog.content = content
        blog.update()
        return self.write(get_json(dict(blog=blog)))


class manage_blogs_edit_handler(Handler):

    def get(self,blog_id):
        logging.warn("api_blog_edit")
        blog = Blog.get(blog_id)
        if blog is None:
            raise APIResourceNotFoundError('Blog')
        return self.render("manage_blog_edit.html",id=blog.id, name=blog.name, summary=blog.summary, content=blog.content, action='/api/blog/%s' % blog_id, redirect='/manage/blogs', user="")


#
# def _get_page_index():
#     page_index = 1
#     try:
#         page_index = int(ctx.request.get('page', '1'))
#     except ValueError:
#         pass
#     return page_index

class Manage_UserList_handler(Handler):
    def get(self):
        return self.render("manage_user_list.html")

class api_get_users(Handler):
    def get(self):
        total = User.count_all()
        page_index=self.request.get("page",'1')
        if page_index=="":
            page_index=1
        else:
            page_index=int(page_index)
        page = Page(total,page_index)
        users = User.find_by('order by created_at desc limit ?,?', page.offset, page.limit)
        for u in users:
            u.password = '******'
        return self.write(get_json(dict(users=users, page=page)))

class Manage_CommentList_handler(Handler):
    def get(self):
        return self.render("manage_comment_list.html")

class api_get_comments(Handler):
    def get(self):
        total = Comment.count_all()
        page_index=self.request.get("page",'1')
        if page_index=="":
            page_index=1
        else:
            page_index=int(page_index)
        page = Page(total,page_index)
        comments = Comment.find_by('order by created_at desc limit ?,?', page.offset, page.limit)
        return self.write(get_json(dict(comments=comments, page=page)))



class api_create_blog_comment_handler(Handler):
    def post(self,blog_id):
        user=self.user
        if user is None:
            raise APIPermissionError('Need signin.')
        blog = Blog.get(blog_id)
        if blog is None:
            raise APIResourceNotFoundError('Blog')

        # content = ctx.request.input(content='').content.strip()
        content = self.request.get("content").strip()
        if not content:
            raise APIValueError('content')
        c = Comment(blog_id=blog_id, user_id=user.id, user_name=user.name, user_image=user.image, content=content)
        c.insert()
        return self.write(get_json(dict(comment=c)))


class peraonal_page_handler(Handler):
    def get(self):
        return self.render("personal_page.html")

app = webapp2.WSGIApplication([
    ('/?', MainPage),
    ('/blog/?', MainPage),
    ('/blog/newpost',Add_blog),
    ('/blog/([0-9a-zA-Z]+)',BlogPage),
    ('/signup/?',Signup_handler),
    ('/welcome/?',Welcome_handler),
    ('/signin/?',Login_handler),
    # ('/signout/?',signout_handler),
    ('/blog.json/([0-9a-zA-Z]+)',blog_json_handler),
    ('/blog.json/?', MainPage_json_handler),
    ('/hello/?', hello_world_handler),
    ('/signout/?',Logout_handler),

    ('/manage/blogs',Manage_blogList_handler),
    ('/api/blogs',api_get_blogs),
    ('/api/blog/delete/([0-9a-zA-Z]+)',api_blog_delete),
    ('/api/blog/([0-9a-zA-Z]+)',api_blog),
    ('/manage/blogs/edit/([0-9a-zA-Z]+)',manage_blogs_edit_handler),

    ('/manage/users',Manage_UserList_handler),
    ('/api/users',api_get_users),

    ('/manage/comments',Manage_CommentList_handler),
    ('/api/comments',api_get_comments),

    ('/api/blogs/([0-9a-zA-Z]+)/comments',api_create_blog_comment_handler),


    ('/me',peraonal_page_handler),

], debug=True)

application = sae.create_wsgi_app(app)

