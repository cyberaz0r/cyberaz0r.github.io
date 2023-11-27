---
layout: post
title:  "Released IIS Tilde Enumeration Scanner 2.0 for HackInBo security conference"
description: "In occasion of the HackInBo security conference, where I will talk about IIS Tilde Enumeration, I released the version 2.0 of the Burp extension that completely refactors the code, fixes a lot of bugs and adds some nice features."
date:   2023-06-07
categories: tools
share: true
tags:
 - tools
 - burp-extension
 - iis-tilde-enumeration
 - hackinbo
 - conference
---

[![Burp extension logo]({{'/assets/images/burpext.jpg'}})](https://github.com/cyberaz0r/Burp-IISTildeEnumerationScanner)

# Introduction
In the [last blog post](/2021/12/published-iis-tilde-enumeration-scanner-burp-extension/) i introduced the first release of the IIS Tilde Enumeration Scanner Burp extension.

In occasion of the HackInBo conference, where I will talk about this vulnerability presenting the extension and analyzing the real exploitation case on portswigger.net, I decided to dust off the code of the extension and refactored it completely to release v2.0.

# Changes
The 2.0 version introduces a lot of changes in the Burp extension:
* Completely refactored code (ate all the spaghetti, now it is fine ;) )
* Upgraded threading system to a completely new and improved version to address threading-related bugs such as bruteforce running after stopping and issues with the scan/stop button not starting or stopping the scan correctly
* Adjusted default configuration values and some active scan parameters to improve accuracy of detection
* Enhanced dynamic values cleaning by utilizing double-request strip in detection mode to reduce false positive ratio and by incorporating more regexes in bruteforce mode to improve bruteforcing accuracy
* Added dynamic content strip level configuration value to select level of dynamic content stripping with additional regexes
* Added delay between requests configuration value to specify the delay between request in milliseconds
* Added Intruder Payload Set Generator to guess complete file names from scan results using sitemap URLs
* Improved match list building on complete filename guessing
* Improved name and extension prefixes feature and fixed some bugs on it
* Fixed duplicates with unfinished extension in results display
* Fixed some syncronization issues with output and better UI handling on starting/stopping scan
* Fixed wordlist fields height in UI
* Fixed some typos and rephrased some parts
* Changed detection confidence to "Firm" (there can be false positives, it is never certain!)
* Changed issue references to the original research paper for issue background and Microsoft workaround for remediation background

All these changes have already been merged in the [GitHub repository](https://github.com/cyberaz0r/Burp-IISTildeEnumerationScanner).

# Download and installation
It is possible to download the extension jar file from [here](https://github.com/cyberaz0r/Burp-IISTildeEnumerationScanner/releases/download/v2.0/Burp-IISTildeEnumerationScanner-all-2.0.jar) and install it by adding it to Burp Suite through the Burp Extender functionality.

The extension will be also updated in the BApp Store, so soon it will be possible to upgrade it directly from there.

# HackInBo conference talk
One thing I always noticed is that, despite its commonness and widespreadness, very few people knew this vulnerability, and there were too few articles online about it. So, to spread awareness about this vulnerability, I decided to talk about it in HackInBo: a security conference held in Bologna, Italy.

The talk's abstract is the following:
>IIS Tilde Enumeration is a security misconfiguration that allows enumeration of filenames and directories on IIS web servers, through which an attacker can access files that a sysadmin would consider "well-hidden".
>
>It is a vulnerability covered with mystery: despite more than 10 years having passed since its public disclosure it is still a common and widespread issue, and yet very unfamiliar to most people.
>
>In this talk we're going to delve deeper into this evergreen vulnerability by exploring its history to uncover the reasons behind the issue, examining the logic behind it to understand how it works, and by showing its full exploitation process through the study of a real-case scenario found in December 2021 on "portswigger.net" as an example.

Unfortunately, despite the presentation slides are written in english language, since HackInBo is an italian conference the talk will be held in italian spoken language.

**UPDATE** The [slides](https://raw.githubusercontent.com/drego85/HackInBo/master/Slide/2023.06.10_Ventesima_Edizione/01_IIS_Tilde_Enumeration_an_evergreen_vulnerability.pdf) and [video](https://www.youtube.com/watch?v=JJ35nVqUBUI) of the talk are now publicly available!