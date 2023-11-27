---
layout: post
title:  "Published IIS Tilde Enumeration Scanner Burp Suite extension"
description: "Released the first version of the IIS Tilde Enumeration Scanner: a Burp Suite extension to detect and exploit this mysterious vulnerability that affected even portswigger.net!"
date:   2021-12-18
categories: tools
share: true
tags:
 - tools
 - burp-extension
 - iis-tilde-enumeration
 - portswigger
 - bug-bounty
---

[![Burp extension logo]({{'/assets/images/burpext.jpg'}})](https://github.com/cyberaz0r/Burp-IISTildeEnumerationScanner)

# Introduction: what is IIS Tilde Enumeration
IIS Tilde Enumeration (or IIS 8.3 Short Name Disclosure) is a vulnerability that allows to enumerate the 8.3 ﬁlenames on the Microsoft Internet Information Services web server.

For more details about how this vulnerability works please refer to [the discoverer's research paper](https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf).

It is a vulnerability covered with mystery: despite almost 10 years having passed since its public disclosure it is still a common and widespread issue (~60-70% of IIS web servers I encountered during WAPTs were vulnerable), and yet very unfamiliar to most people.

So, intrigued by its history and fascinated about the way it worked, I decided to write a Burp Suite extension about this vulnerability, in order to facilitate its exploitation during pentests and in the same time study the vulnerability and learn to code Burp Suite extensions.

# Features of the Burp extension
This extension will add an Active Scanner check for detecting IIS Tilde Enumeration vulnerability and add a new tab in the Burp UI to manually check and exploit the vulnerability

In the Burp UI tab you can:
* Check if a host is vulnerable without exploiting the vulnerability
* Exploit the vulnerability by enumerating every 8.3 short name in an IIS web server directory
* Configure the parameters used for the scan and customize them in any way you want
* Edit the base request performed (you can add headers, cookies, edit the User Agent, etc)
* Save the scan output to a file


# Fun fact: IIS Tilde Enumeration in portswigger.net
During the development of the extension, while I was deep in the rabbit hole of the Burp Extender API's documentation, I noticed that the PortSwigger forum had a `Discussion.aspx` page, which made me realize that portswigger.net was running IIS.

![Vsauce meme]({{'/assets/images/vsauce.jpg'}})

So I tried to scan it using my own extension on it and suprisingly I found out that "portswigger.net" was vulnerable!

I reported the issue to their Bug Bounty program via [HackerOne](https://hackerone.com/portswigger) and received a $250 bounty, which may be considered as a low reward for a bug bounty, but I don't care since for me finding a totally unexpected bug on PortSwigger is priceless!

# Source, download and installation
The source code of the Burp extension is available on the [GitHub repository](https://github.com/cyberaz0r/Burp-IISTildeEnumerationScanner).
It is possible to directly download the jar file from [here](https://github.com/cyberaz0r/Burp-IISTildeEnumerationScanner/releases/download/v1.0/Burp-IISTildeEnumerationScanner-1.0.jar) and install it by adding it to Burp Suite through the Burp Extender functionality.

**UPDATE**: The extension has been added to the BApp Store, so it is possible to download and install it directly from there.