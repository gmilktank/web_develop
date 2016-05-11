import webapp2
import cgi
import string
import re

def escape_html(s):
    return cgi.escape(s,quote="True")

form_html="""
<form>
<h2> Add a Food </h2>
<input type="text" name="food" >
%s
<button>Add </button>
</form>
"""


hidden_html="""
<input type="hidden" name="food" value="%s">
"""

shopping_list_html="""
<br>
<br>
<h2>Shopping List:</h2>
<ul>
%s
</ul>

"""

item_html="<li>%s</li>"


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.write(*a,**kw)


class MainPage(Handler):
    def write_form(self,error=""):
        self.response.write(form_html)

    def get(self):
        output=form_html
        output_html=""
        output_items=""
        items=self.request.get_all("food")
        if items:
            for item in items:
                output_html+=hidden_html%item
                output_items+=item_html%item
            output_shopping=shopping_list_html%output_items
            output+=output_shopping

        output=output%output_html


        self.write(output)

    def post(self):
        self.response.write("Thanks")





app = webapp2.WSGIApplication([
    ('/', MainPage),

], debug=True)
