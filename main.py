from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

import tlslite.keyfactory 
import tlslite.compat 
import tlslite.cryptomath 
from tlslite.RSAKey import RSAKey 
from base64 import b64encode, b64decode

import re
import time
import random

PK = """-----BEGIN RSA PRIVATE KEY-----
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==
-----END RSA PRIVATE KEY-----"""

class MainPage(webapp.RequestHandler):

    def get(self):

        self.response.out.write("""<html><body>""")
        self.response.out.write("""<h1>Spotnet Signature Service</h1>""")
        self.response.out.write("""</body></html>""")

class MagicXML(webapp.RequestHandler):

    def post(self):

        zTitle = b64decode(self.request.get('title')).replace("|","")

        if len(zTitle) == 0: self.response.out.write(""""""); return;

        hCat = int(self.request.get('cat'))
        hSize= int(self.request.get('size'))

        ImgX = int(self.request.get('imgx'))
        ImgY = int(self.request.get('imgy'))

        zTag = re.sub(r'\W', '', self.request.get('tag'))
        sCat = str(re.sub(r'\W', '', self.request.get('sub')))
        zPoster = re.sub(r'\W', '', self.request.get('from'))

        zDesc = b64decode(self.request.get('desc'))
        zNZB = b64decode(self.request.get('msgid'))
        zUrl = b64decode(self.request.get('link'))
        zImg = b64decode(self.request.get('img'))
        zImage = b64decode(self.request.get('image'))

        if len(sCat) == 0: self.response.out.write("""E1"""); return;
        if len(zPoster) == 0: self.response.out.write("""E3"""); return;
        if len(zDesc) == 0: self.response.out.write("""E4"""); return;
        if len(zNZB) == 0: self.response.out.write("""E5"""); return;

		KeyID = int('9999')

        PostID = int(get_count('Cnt')) + 1 
        increment('Cnt')

        if not PostID == int(get_count('Cnt')): self.response.out.write("""PostID Error"""); return;

        secs = int(time.time())
        
        zHeader = str(hCat).replace(".","") + str(KeyID) + sCat.replace(".","") + '.' + str(hSize) + '.' + str(PostID) + '.' + str(secs) + '.1.NL'

        zKey = tlslite.keyfactory.parsePEMKey(PK, private=True)

        zMagic = unicode(zTitle, 'latin-1') + zHeader + zPoster

        zHash = tlslite.cryptomath.bytesToBase64(zKey.hashAndSign 
(tlslite.compat.stringToBytes(zMagic.encode('latin-1')))) 

        zHeader = zHeader + '.' + zHash.replace("/", "-s").replace("+", "-p").replace("=", "")

        zXML = '<Spotnet><Posting>'
        zXML = zXML + '<Key>3</Key>'
        zXML = zXML + '<Created>' + str(secs) + '</Created>'
        zXML = zXML + '<Poster>' + zPoster.replace("<", "").replace(">", "") + '</Poster>'
        if len(zTag) > 0: zXML = zXML + '<Tag>' + zTag.replace("<", "").replace(">", "") + '</Tag>';
        zXML = zXML + '<Title><![CDATA[' + unicode(zTitle.replace("]]>"," "), 'latin-1').encode('ascii', 'xmlcharrefreplace') + ']]></Title>'
        zXML = zXML + '<Description><![CDATA[' + unicode(zDesc.replace("]]>"," "), 'latin-1').encode('ascii', 'xmlcharrefreplace') + ']]></Description>'
        if len(zUrl) > 0: zXML = zXML + '<Website><![CDATA[' + unicode(zUrl.replace("]]>"," "), 'latin-1').encode('ascii', 'xmlcharrefreplace') + ']]></Website>';
        if len(zImage) > 0: zXML = zXML + '<Image><![CDATA[' + unicode(zImage.replace("]]>"," "), 'latin-1').encode('ascii', 'xmlcharrefreplace') + ']]></Image>';
        if len(zImg) > 0: zXML = zXML + "<Image Width='" + str(ImgX) + "' Height='" + str(ImgY) + "'>"; zXML = zXML + '<Segment>' + zImg.replace("<", "").replace(">", "") + '</Segment>'; zXML = zXML + "</Image>";
        zXML = zXML + '<Size>' + str(hSize) + '</Size>'
        zXML = zXML + '<Category>0' + str(hCat) 
        for item in [sCat[i:i+3] for i in range(0, len(sCat), 3)]: zXML = zXML + '<Sub>0' + str(hCat) + item.replace("<", "").replace(">", "") + '</Sub>';
        zXML = zXML + '</Category>'
        zXML = zXML + '<NZB>'
        for item in zNZB.split(' '): zXML = zXML + '<Segment>' + item.replace("<", "").replace(">", "") + '</Segment>';
        zXML = zXML + '</NZB>'
        zXML = zXML + '</Posting></Spotnet>'

        zHash2 = tlslite.cryptomath.bytesToBase64(zKey.hashAndSign 
(tlslite.compat.stringToBytes(zXML.encode('latin-1')))) 

        zHash2 = zHash2.replace("/", "-s").replace("+", "-p").replace("=", "")
        
        self.response.out.write(zHeader + ' ' + zHash2 + ' ' + zXML)

class Cnt(db.Model):
    count = db.IntegerProperty(required=True, default=0)

def increment(name):
    def txn():
        counter = Cnt.get_by_key_name(name)
        if counter is None: counter = Cnt(key_name=name);
        counter.count += 1
        counter.put()
    db.run_in_transaction(txn)

def get_count(name):
    counter = Cnt.get_by_key_name(name) 
    if counter is None: counter = Cnt(key_name=name);
    return counter.count 
        
application = webapp.WSGIApplication(
                                     [('/', MainPage),
                                     ('/signxml', MagicXML)],
                                     debug=False)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
