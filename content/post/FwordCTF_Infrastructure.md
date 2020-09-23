---
title: International CTF Infrastructure Management
summary: How to deploy a scalable and robust CTF infrastructure and the different issues we faced in FwordCTF 2020
date: "2020-09-22T00:08:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: ""
  image: "arch.jpg"
---

Last month our team organized **FwordCTF 2020**  and we got very positive feedbacks and fortunately most of the players enjoyed their journey. More than 1900 participants and 980 teams took part of this first edition, as I was responsible of managing the infrastructure it was a great challenge to deal with this great number and create a secure environment for unsecure challenges :v so i'll share with you my experience maybe it can inspire you.

**NOTE:** This is not a step by step tutorial, it's my way to document things so I can remember them next year.

![STATS](https://i.imgur.com/Mw8OoKF.png)

**Cloudflare Stats:**

![STATS](https://i.imgur.com/uTuxI3U.png)

## Sections ##

* Platform Infrastructure 
* Issues We faced
* Challenges Management and health check
* Isolated Container for each participant in Bash category
* Next edition ?

## Platform Infrastructure ##

We have mainly used AWS services, there is no special reason for this choice but I was more familiar with AWS and every member in our team had free 100$ credits in AWS Educate xD 
For impatient people here is the global architecture we used at the beginning of the CTF, it was the ideal choice for us but we faced some problems that obliged us to switch to an another alternative.

![PLATFORM](https://i.imgur.com/OFQnrbj.jpg)

**Details:**

* 4 * CTFD Instance: Ubuntu Server 20.04 LTS t2.medium (__4Gb Memory / 2 * Vcpus__) : a docker swarm Master Node + 3 * Worker nodes (more details later)
* Redis caching instance: Ubuntu Server 20.04 LTS t2.small (__2Gb Memory / 1 * Vcpus__) : A separate instance for Redis ( caching system )
* Bastion: Ubuntu Server 20.04 LTS t2.small (__2Gb Memory / 1 * Vcpus__): As you can notice all CTFD and redis instances are in a private subnet so we can't SSH to them that's why we need a bastion that is in a public subnet, and as all the subnets are in the same VPC so we can SSH from Bastion to the servers in the private subnet.
* Amazon RDS Instance: db.t2.small at the beginning then upgraded it to db.t2.medium: Amazon RDS is a nice way to set up, operate, and scale a relational database in the cloud. It has also a nice automated backup system.

![RDS](https://imgur.com/VDq02s8.png)

* Cloudflare free plan: Cloudflare really saved us a lot , we faced more than DDOS attacks and some of them were really serious attacks but hackers can't be hacked easily :p 

![ATTACKS](https://imgur.com/NQr71W6.png) 

* Sendgrid free account (25k free emails): We used Sendgrid for email verification and for sending the certificates after the CTF.
* AWS Network Load Balancer

![LOADBALANCER](https://imgur.com/zkGzWBn.png)

* AWS S3 bucket to serve the files to download.

![S3](https://imgur.com/Znt636a.png)

* NAT Gateway: NAT gateway is important to enable internet connection for the private subnets.

![NAT](https://imgur.com/sKI36vv.png)

**VPC:**

![VPC](https://i.imgur.com/7jcwuKM.jpg)

**Subnets:**

![SUBNETS](https://imgur.com/pcNCzJe.png)

We used docker swarm for orchestration and it was really helpful , we created 4 replicas in each node ( learn more about Docker Swarm [here](https://www.ionos.fr/digitalguide/serveur/know-how/docker-orchestration-avec-swarm-et-compose/) ) but after some time we decided to change our strategy , docker swarm had a weakness which is sharing **volumes** ; every volume mount is local to that node, this was not something critical and there are some solutions available but as it was something unpredictable for us and we didn't test it before, we decided to choose the safest option and replaced the 4 CTFD instances with a single t2.xlarge instance ( __16GB Memory/4 Vcpus__ ) that contains also 4 replicas of CTFD . The result is the following:

![ARCH](https://i.imgur.com/WVm0KA5.jpg)

## Issues We faced ##

### AWS RDS ###

We are really thankful that this error occured 5 days before the CTF. Only 1 hour after the we launched the platform, we kept having internal server errors , after some debugging we discovered AWS RDS (mysql DBs in general) has an attribute **max_connections** which is set by default to a low value and once we exceeded that value CTFD couldn't connect to the database, but after changing the max_connections value and restarting things we kept having the 500 internal errors :( . After a lot of debugging and analysis I discovered that the containers couldn't resolve the database domain name which is really strange because AWS DNS server was running flawlessly. To make things shorter, docker swarm overlay network's IP range was overlapping with the physical network, so when the container try to resolve the DB domain name it didn't really send a request to AWS DNS , the solution was to launch the swarm with the following command:
```sh
sudo docker swarm init --default-addr-pool 192.168.0.0/16
```
it took us only 35 minutes to discover the problem and solve it, but it was the most stressful minutes in my life xD

### Common problems ###

**Docker Swarm sticky sessions**

Docker swarm doesn't have by default a layer 7  load balancer , so we had faced some problems related to sessions, the solution was easy, we only needed to add our own load balancer that supports sticky sessions (we used traefik instead of nginx and it did really great )

**Other Issues**

I needed to set __SQLALCHEMY_MAX_OVERFLOW__ in CTFD to a high value in order to avoid some DB problems and I also had to add some code to CTFD in order to connect successfully to my S3 bucket (AWS Educate accounts have an extra parameter that need to be used and CTFD doesn't handle this case). 

## Challenges Management and health check ##

For Web tasks every framework needs a custom docker-compose.yml file so every author took care of his task.
For the other categories we used a t2.medium instance for each task and docker swarm to orchestrate the containers ( each task has 3 replicas) and to make sure that we will have no down time (if a container failed there is always two other containers running). this is an automated version where you only have to create a Dockerfile for the task (take a look at my github repo for examples):

**Steps:**
* Put the following docker-compose.yml file in the same directory with the task:

```yaml
version: "3.8"
services:
  task:
    image: 127.0.0.1:5000/task
    build:
      context: .
      dockerfile: ./Dockerfile
    container_name: taskName
    deploy:
      mode: replicated
      replicas: 3
    networks:
      - isolated
    ports:
      - "9999:1234" #ToChange
networks:
  isolated:
```

* Choose the port you want
* Run the following start.sh with root privileges

```sh
#!/bin/bash
echo "[!] Run me with sudo pleaaaaase!"
docker run -it --name registry -p 127.0.0.1:5000:5000 -d registry:2
if [ $? -eq 0 ]; then
echo "[+] registry done!"
else
    echo "Failed"
fi
docker-compose -f docker-compose.yml build
docker-compose -f docker-compose.yml push
if [ $? -eq 0 ]; then
  echo "[+] Image pushed!"
else
    echo FAILED
fi
docker swarm init
docker stack deploy --compose-file docker-compose-sample.yml task
if [ $? -eq 0 ]; then
echo "[+] Done, Fword FTW"
else
    echo FAILED
fi
```
__NOTE:__ In case you faced any errors you have to leave the swarm and retry again (don't forget to use the last version of docker-compose)

This was a quick solution to facilitate things during the CTF and it may be optimized, in fact I'm thinking of releasing a tool that do everything for us but I'm just too lazy.

### Mangement: ###

Some of you may be wondering how we could manage more than 22 servers, we used an awesome tool called **[Termius](https://termius.com/)** (it's free in Github Student Pack) which is an SSH client with a lot of awesome features, it lets you organize the servers in groups and ssh to them with just a double click.

![TERMIUS](https://i.imgur.com/PFWeLl2.png)

**Platform:**

![TERMIUS](https://i.imgur.com/6KvLoHv.png)

## Isolated Container for each participant in Bash category ##

I think that many people are waiting for this section, in bash category there were some tasks that required an SSH connection so to provide a better environment we came up with this solution and every player will be assigned to an isolated container.

**Technical details:**

The idea is simple, we firstly instanciate a manager which is a container running the SSH server and for each connection it will instanciates a new container (from the image of the task) and connects to it (docker inside docker).

It may look simple but it took me a little bit of time to implement it and test it. Please take a look at this **[sample](https://github.com/kahla-sec/FwordCTF-2020/tree/master/Bash/CapiCapi)** if you want to adapt this method.

__Steps:__

1) Run ```docker-compose -f docker-compose-task.yml build```
2) Run ```docker-compose -f docker-compose.yml up```

And Bingo you will have SSH listening on port 10000, you can create a cron job to kill the participants containers every period of time or optimize manage.sh script. Please feel free to contact me if you have any questions or optimizations.


## Next edition ? ##

Personally, I prefer using kubernetes in the next edition and automate health checks for each task. Finding a solution to enable a separate environment for every participant in all categories is also a nice idea and finally develop our custom platform.

## Conclusion ##

I'm so happy this edition was concluded successfully and we got great feedbacks, I have definitely learned a lot from this opportunity, can't wait for the next edition ; it will be  more exciting !!
For any questions you can contact me on twitter or facebook!

