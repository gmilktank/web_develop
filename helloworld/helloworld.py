import webapp2
import cgi
import string
import re

def escape_html(s):
    return cgi.escape(s,quote="True")


form="""
<form method="post" >
    what's your birthday?
    <br>
    <label>Year
    <input name="year">
    </label>

    <label>Month
    <input name="month">
    </label>

    <label>
    Day
    <input name="day">
    </label>

    <br>
    <div style="color: red">%(error)s</div>
    <br>

	<input type="submit">
</form>

"""


rot13_form="""
<h>Enter some text to ROT13
<form method="post">
    <textarea name="text">%(inner_text)s</textarea>
    <input type="submit">

</form>

"""


sign_up_form="""
<h>SignUp
<form method="post">
    <label>
    User Name:
    <input name="username" value="%(username)s"> <div style="color: red">%(error1)s</div>
    </label><br>
    <label>
    Password:
    <input name="password" type="password"> <div style="color: red">%(error2)s</div>
    </label><br>
    <label>
    Verify Password:
    <input name="verify" type="password"><div style="color: red">%(error3)s</div>
    </label><br>
    <label>
    E-mail:
    <input name="email" value="%(email)s"><div style="color: red">%(error4)s</div>
    </label><br>
    <br>
    <br>
    <input type="submit">

</form>



"""




class MainPage(webapp2.RequestHandler):
    def write_form(self,error=""):
        self.response.write(form %{"error":error})

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.write_form()

    def post(self):
        self.response.write("Thanks")


class TestHandler(webapp2.RequestHandler):
    def get(self):
        q=self.request.get("q")
        self.response.write(q)
        # self.response.headers['Content-Type'] = 'text/plain'
        # self.response.write(self.request)

    def post(self):
        # q=self.request.get("q")
        # self.response.write(q)
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(self.request)


def rot13_encode(s):
    offSet=13;
    # a='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    # b='NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    d={chr(i+c) : chr((i+offSet) % 26 + c) for i in range(26) for c in (65,97)}
    return ''.join([d.get(c, c) for c in s])




class rot13Handler(webapp2.RequestHandler):
    def write_form(self,inner_text=""):
        self.response.write(rot13_form %{"inner_text":inner_text})



    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.write_form()



    def post(self):

        self.write_form(escape_html( rot13_encode(self.request.get("text"))))


def valid_username(username):
    USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)

def valid_password(password):
    PASSWORD_RE=re.compile(r".{3,20}$")
    return PASSWORD_RE.match(password)

def valid_email(email):
    EMAIL_RE=re.compile(r"^[\S]+@[\S]+.[\S]+$]")
    return EMAIL_RE.match(email)


class signup_handler(webapp2.RequestHandler):
    def write_form(self,username="",email="",error1="",error2="",error3="",error4=""):
        self.response.write(sign_up_form%{"username":username,"email":email,"error1":error1,"error2":error2,"error3":error3,"error4":error4})

    def get(self):
        self.write_form()

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

        if error1+error2+error3+error4=="":
            self.redirect("/unit2/signup/welcome?username="+username)
        else:
            self.write_form(escape_html(username),escape_html(email),error1,error2,error3,error4)

        #self.write_form()


class welcome_handler(webapp2.RequestHandler):
    def get(self):
        self.response.write("Weclome"+self.request.get("username"))

app = webapp2.WSGIApplication([
    ('/', MainPage),('/testform',TestHandler),
    ('/unit2/rot13',rot13Handler),
    ('/unit2/signup',signup_handler),
    ('/unit2/signup/welcome',welcome_handler),

], debug=True)
