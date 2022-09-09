---
layout: post
title: Configuring email notifications for HTML Smuggled files using Download Blocker and IFTTT
tags: [blueteam, html_smuggling, IFTTT, T1027.006, T1027]
---

# Introduction

In this blog post I will show you how to receive email notifications when a download triggers a [Download Blocker](https://chrome.google.com/webstore/detail/download-blocker/kippogcnigegkjidkpfpaeimabcoboak) rule.

You will need to create an account with IFTT with the email address you want the notifications to be sent to.  

1) Go to [https://ifttt.com/create](https://ifttt.com/create) and click Add.

![IFTTT - Step 1](/assets/img/downloadblocker-ifttt/1.PNG)

2) For the trigger, search webhooks and choose "Receive a web request".

![IFTTT - Step 2](/assets/img/downloadblocker-ifttt/2.PNG)

3) Choose an event name, e.g. DownloadBlocker and click "Create Trigger"

![IFTTT - Step 3](/assets/img/downloadblocker-ifttt/3.PNG)

4) For the action, search for and choose Email.

![IFTTT - Step 4](/assets/img/downloadblocker-ifttt/4.PNG)

5) Enter your desired subject, and for the body, just type \{\{Value1\}\} and then click "Update action", "Continue" and finally "Finish" to save your applet.

![IFTTT - Step 5](/assets/img/downloadblocker-ifttt/email.PNG)<br>
![IFTTT - Step 5](/assets/img/downloadblocker-ifttt/overview.PNG)<br>
![IFTTT - Step 5](/assets/img/downloadblocker-ifttt/finish.PNG)

6) Next, go to [https://ifttt.com/maker_webhooks](https://ifttt.com/maker_webhooks).

![IFTTT - Step 6](/assets/img/downloadblocker-ifttt/webhooks.PNG)

Select Documentation and make a note of your API Key.

![IFTTT - Step 7](/assets/img/downloadblocker-ifttt/key.PNG)

7) Now, go to [https://ifttt.com/settings](https://ifttt.com/settings) and scroll down to "URL shortening". Uncheck "Auto-shorten URLs" and save your changes.

![IFTTT - Step 8](/assets/img/downloadblocker-ifttt/urls.PNG)

### Configuring Download Blocker

To generate the webhook URL, you need to take your event name from step 2, as well as your API key:

https://maker.ifttt.com/trigger/[Event Name Here]/with/key/[API Key Here]  

e.g. https://maker.ifttt.com/trigger/DownloadBlocker/with/key/abcdefghijklmnopqrstuvwxyz

You will need to configure Download Blocker to send download alerts to this URL. Instructions explaining how to do this are available [here](https://github.com/SecurityJosh/DownloadBlocker#configuration).

### Example Download Blocker Config

This is just an example config, you will need to modify it to fit your requirements. You should check the list of available [placeholders](https://github.com/SecurityJosh/DownloadBlocker#alerts-optional) as this example config may not be up to date.

{% highlight json %}
{
  "rules": [
    {
      "bannedExtensions": [
        "*"
      ],
      "origin": "local",
      "action": "block"
    }
  ],
  "alertConfig": {
    "url": "https://maker.ifttt.com/trigger/[Event Name Here]/with/key/[API Key Here]",
    "headers": {},
    "method": "POST",
    "sendAsJson": false,
    "postData": {
      "value1": "<span style='white-space: nowrap'><b>Filename:</b> {filename}<br><b>File URL:</b> {fileUrl}<br><b>URL:</b> {url}<br><b>SHA256:</b> {sha256}<br><b>Download Created:</b> {formattedTimestamp} ({timestamp})<br><b>Event Time:</b> {formattedEventTimestamp} ({eventTimestamp})<br><b>Rule name:</b> {ruleName}<br><b>Action:</b> {action}<br><b>State:</b> {state}<br><b>File Inspection:</b> {fileInspection}<br><b>Hostname:</b> {hostname}<br><b>Username:</b> {username}</span>"
    }
  }
}
{% endhighlight %}

### Result

![Generated Email](/assets/img/downloadblocker-ifttt/generated_email.png)