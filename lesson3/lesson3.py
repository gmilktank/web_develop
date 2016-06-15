import webapp2
import cgi
import os
import string
import re
import jinja2
from google.appengine.ext import db
def escape_html(s):
    return cgi.escape(s,quote="True")



template_dir = os.path.join(os.path.dirname(__file__), "templates")

jinja2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),autoescape=True)



def render_str(template, **params):
    t = jinja2_env.get_template(template)
    return t.render(params)

class Blog(db.Model):
    title=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    last_modified=db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text=self.content.replace('\n','<br>') #without this replace .all the outcome will in one line.
        return render_str("blogpage.html",p=self)


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.write(*a,**kw)

    def render_str(self,template,**params):
        t=jinja2_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

class MainPage(Handler):
    def write_form(self,error=""):
        self.response.write()

    def get(self):
        blogs=db.GqlQuery("select * from Blog order by created DESC")
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
            a=Blog(title=title,content=content)
            a.put()

            self.redirect('/blog/%s' %str(a.key().id()))

    def get(self):
        self.render("add_blog.html")


class BlogPage(Handler):
    def get(self,blog_id):
        key=db.Key.from_path('Blog',int(blog_id))
        blog=db.get(key)
        if not blog:
            self.error(404)
            return
        self.render("perment_link.html",blog=blog)




app = webapp2.WSGIApplication([
    ('/blog/?', MainPage),
    ('/blog/newpost',Add_blog),
    ('/blog/(\d+)',BlogPage)

], debug=True)
