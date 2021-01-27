---
layout: post
title: Detecting HTML smuggling attacks using Sysmon and Zone.Identifier files
tags: [sysmon, blueteam, html_smuggling]
---

{% assign yes ="<span style='color:green'>Yes</span>" %}
{% assign no="<span style='color:red'>No</span>" %}

# Introduction

In this blog post I will show you how to detect HTML Smuggling attacks using Sysmon. I'm going to assume you are familiar with the concept of NTFS Alternate Data Streams, and how the Zone.Identifier ADS is used to mark files downloaded from the internet. If you aren't, this [post](https://textslashplain.com/2016/04/04/downloads-and-the-mark-of-the-web/) by Eric Lawrence is a great primer.

HTML Smuggling is a technique used to bypass perimeter defenses, such as web proxies and secure email gateways. A file is 'smuggled' into the body of a HTTP response, and is downloaded to the user's machine using JavaScript. This means that the perimeter defenses will only see the web page, and not the smuggled file. [Outflank](https://outflank.nl/blog/2018/08/14/html-smuggling-explained/) and [NCC Group](https://www.nccgroup.com/uk/about-us/newsroom-and-events/blogs/2017/august/smuggling-hta-files-in-internet-exploreredge/) have covered the technique in more detail.

## Sysmon ID 15 (FileCreateStreamHash)

As of version [11.10](https://blog.knogin.com/sysmon-11.10-threat-detection), Sysmon has the ability to record the contents of an ADS. Therefore, if HTML Smuggling leaves unique artifacts in the Zone.Identifier ADS, then we can use Sysmon to detect that HTML Smuggling has taken place.

## Testing Methodology

To test each browser, I used [this](https://www.outflank.nl/demo/html_smuggling.html) document from [Outflank.nl](https://outflank.nl). In each browser, I opened the document via its original URL, as well as via a locally saved copy. This was to determine if the browser treated the downloaded file differently depending on the protocol used (http:// or https:// vs file://).

## Results

### Browser Versions Tested

* Google Chrome Version 88.0.4324.96 (Official Build) (64-bit)
* Mozilla Firefox Version 84.0.2 (64-bit)
* Microsoft Edge (Chromium) Version 88.0.705.50 (Official build) (64-bit)
* Microsoft Edge (Legacy) Version 44.18362.449.0

*N.B. Going forward, by 'smuggling page' I mean e.g. https://www.outflank.nl/demo/html_smuggling.html or C:\Users\Joshua\Downloads\html_smuggling.html* 

Google Chrome, Firefox and Chromium Edge all demonstrated the same behavior. For both the hosted and the local smuggling page, the Zone.Identifier ADS was created, but the HostUrl property is set to **about:internet**, instead of the originating page.

![Sysmon HTML Smuggling Event - Chrome, Firefox and Chromium Edge](/assets/img/sysmon-htmlsmuggling/firefox.png)

Legacy Edge, on the other hand, treats these files differently. When the smuggling page is served over HTTP(S), the Zone.Identifier ADS is created, and the HostUrl property is set to be the originating page, propended with **blob:**.

![Sysmon HTML Smuggling Event - Legacy Edge - http://](/assets/img/sysmon-htmlsmuggling/legacyedge_http.png)

When the smuggling page is served locally, Legacy Edge will only create a Zone.Identifier ADS for the downloaded document if the smuggling page also has one. Modern email clients will create a Zone.Identifier ADS for attachments from emails received from the internet, so files downloaded via smuggling page sent via email and opened in legacy edge should still be detected by Sysmon.

In this instance, the HostUrl property will have a null origin, but the ReferrerUrl will point to the smuggling page.

![Sysmon HTML Smuggling Event - Legacy Edge - file://](/assets/img/sysmon-htmlsmuggling/legacyedge_file.png)

## Summary

|                | MOTW Created (http://) | MOTW Created (file://) | Stream contains document URL | HTML Smuggling Identifiable |
|----------------|------------------------|------------------------|------------------------------|-----------------------------|
| Google Chrome  | {{ yes }}              | {{ yes }}              | {{ no }}                     |{{ yes }}                     			   |
| Firefox        | {{ yes }}              | {{ yes }}              | {{ no }}                     |{{ yes }}                    	   	   	   |
| Chromium Edge  | {{ yes }}              | {{ yes }}              | {{ no }}                     |{{ yes }}                    			   |
| Legacy Edge    | {{ yes }}              | It depends*            | {{ yes }}                    | for http://, yes, for file://, it depends *|

\* For local smuggling pages (file://), Legacy Edge only creates a Zone.Identifier ADS for the downloaded file if the smuggling page has one.

## Sysmon Rule

From the above results, we can see that Sysmon can detect HTML Smuggling attacks by looking for Zone.Identifier alternate data streams that contain either of the following values:
* HostUrl=about:internet
* HostUrl=blob:

### Sysmon XML

{% highlight xml %}
<RuleGroup name="" groupRelation="or">
    <FileCreateStreamHash onmatch="include">
	<Rule name="HTML_Smuggling" groupRelation="and">
	    <TargetFilename condition="end with">:Zone.Identifier</TargetFilename>
	    <Contents condition="contains any">blob:;about:internet</Contents>		
	</Rule>
    </FileCreateStreamHash>
</RuleGroup>
{% endhighlight %}

## Previous Work

After I started working on this blog post, I came across a [tweet](https://twitter.com/llt4l/status/1279235127831334912) by [@llt41](https://twitter.com/llt4l), which covers some of the same information as I have here.