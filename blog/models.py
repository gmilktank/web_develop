

import time, uuid
from transwarp.db import next_id
from transwarp.orm import Model, StringField, BooleanField, FloatField, TextField
import json

from tools import *
import index








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
        return index.render_str("blogpage.html",p=self)


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


