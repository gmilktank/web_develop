__author__ = 'milktank'

import time, uuid
from transwarp.db import next_id
from transwarp.orm import Model, StringField, BooleanField, FloatField, TextField
import json


class User(Model):
    __table__ = 'users'

    id = StringField(primary_key=True, default=next_id, ddl='varchar(50)')
    email = StringField(updatable=False, ddl='varchar(50)')
    password = StringField(ddl='varchar(50)')
    admin = BooleanField()
    name = StringField(ddl='varchar(50)')
    image = StringField(ddl='varchar(500)')
    created_at = FloatField(updatable=False, default=time.time)

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
        blog={"title":self.title,"content":self.content,"created":str(self.created),"email":self.email,"last_modified":str(self.last_modified)  }
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