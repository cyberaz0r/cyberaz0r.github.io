---
layout: post
title:  Yellowfin Multiple Vulnerabilities
description: Advisory about Stored Cross-Site Scripting and Insecure Direct Object References vulnerabilities found on Yellowfin.
date:   2021-10-14
categories: cve-advisories
share: true
tags:
 - cve-advisories
 - CVE-2021-36387
 - CVE-2021-36388
 - CVE-2021-36389
---

![Yellowfin logo]({{ '/assets/images/yellowfin-logo.jpg' | relative_url }})

# CVE-2021-36387: Stored Cross-Site Scripting

**Affected Products and Versions**: Yellowfin < 9.6.1
**CVSSv3.1 Score:** 5.4 (Medium)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura

## Executive Summary
In Yellowfin before 9.6.1 there is a Stored Cross-Site Scripting vulnerability in the video embed functionality exploitable through a specially crafted HTTP POST request to the page "ActivityStreamAjax.i4".

## Remediation
Update Yellowfin to version 9.6.1 or later.

## Reference
[https://wiki.yellowfinbi.com/display/yfcurrent/Release+Notes+for+Yellowfin+9#ReleaseNotesforYellowfin9-Yellowfin9.6.1](https://wiki.yellowfinbi.com/display/yfcurrent/Release+Notes+for+Yellowfin+9#ReleaseNotesforYellowfin9-Yellowfin9.6.1)

# CVE-2021-36388: Insecure Direct Object Reference

## Vulnerability

**Affected Products and Versions**: Yellowfin < 9.6.1
**CVSSv3.1 Score:** 7.5 (High)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura

## Executive Summary
In Yellowfin before 9.6.1 it is possible to enumerate and download users profile pictures through an Insecure Direct Object Reference vulnerability exploitable by sending a specially crafted HTTP GET request to the page "MIIAvatarImage.i4".

## Remediation
Update Yellowfin to version 9.6.1 or later.

## Reference
[https://wiki.yellowfinbi.com/display/yfcurrent/Release+Notes+for+Yellowfin+9#ReleaseNotesforYellowfin9-Yellowfin9.6.1](https://wiki.yellowfinbi.com/display/yfcurrent/Release+Notes+for+Yellowfin+9#ReleaseNotesforYellowfin9-Yellowfin9.6.1)

# CVE-2021-36389: Insecure Direct Object Reference

**Affected Products and Versions**: Yellowfin < 9.6.1
**CVSSv3.1 Score:** 7.5 (High)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura

## Executive Summary
In Yellowfin before 9.6.1 it is possible to enumerate and download uploaded images through an Insecure Direct Object Reference vulnerability exploitable by sending a specially crafted HTTP GET request to the page "MIImage.i4".

## Remediation
Update Yellowfin to version 9.6.1 or later.

## Reference
[https://wiki.yellowfinbi.com/display/yfcurrent/Release+Notes+for+Yellowfin+9#ReleaseNotesforYellowfin9-Yellowfin9.6.1](https://wiki.yellowfinbi.com/display/yfcurrent/Release+Notes+for+Yellowfin+9#ReleaseNotesforYellowfin9-Yellowfin9.6.1)