# -*- coding:utf-8 -*-
__author__ = 'milktank'

import hmac
import random
SECRET = 'imsosecret'

import re
import string
import hashlib
import time
import datetime
import logging
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
    logging.warning(len(h.split(',')))
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
    dt = datetime.datetime.fromtimestamp(t)
    return u'%s年%s月%s日' % (dt.year, dt.month, dt.day)

from models import Blog
from apis import Page


def get_blog_by_page(page_index):
    total = Blog.count_all()
    page = Page(total, page_index)
    blogs = Blog.find_by('order by created_at desc limit ?,?', page.offset, page.limit)
    return blogs, page