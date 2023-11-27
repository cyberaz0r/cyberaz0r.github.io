---
layout: post
title:  GL.iNet Multiple Vulnerabilities
description: Advisory about Remote Command Execution and Arbitrary File Write vulnerabilities found on GL.iNet routers.
date:   2023-11-27
categories: cve-advisories
share: true
tags:
 - cve-advisories
 - CVE-2023-46454
 - CVE-2023-46455
 - CVE-2023-46456
---

![GL.iNet logo]({{ '/assets/images/gl.inet-logo.png' | relative_url }})

# CVE-2023-46454: Remote Command Execution

**Affected Products and Versions**: GL.iNet GL-AR300M routers with firmware v4.3.7
**CVSSv3.1 Score:** 7.2 (High)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura

## Executive Summary
In GL.iNET GL-AR300M routers with firmware v4.3.7, it is possible to inject arbitrary shell commands through a crafted package name in the package information functionality.

## Remediation
Update GL.iNet GL-AR300M router firmware to the latest version.

## Reference
[https://nvd.nist.gov/vuln/detail/CVE-2023-46454](https://nvd.nist.gov/vuln/detail/CVE-2023-46454)

# CVE-2023-46455: Arbitrary File Write

**Affected Products and Versions**: GL.iNet GL-AR300M routers with firmware v4.3.7
**CVSSv3.1 Score:** 7.2 (High)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura

## Executive Summary
In GL.iNET GL-AR300M routers with firmware v4.3.7, it is possible to write arbitrary files through a path traversal attack in the OpenVPN client file upload functionality.

## Remediation
Update GL.iNet GL-AR300M router firmware to the latest version.

## Reference
[https://nvd.nist.gov/vuln/detail/CVE-2023-46455](https://nvd.nist.gov/vuln/detail/CVE-2023-46455)

# CVE-2023-46456: Remote Command Execution

**Affected Products and Versions**: GL.iNet GL-AR300M routers with firmware v3.216
**CVSSv3.1 Score:** 7.2 (High)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura

## Executive Summary
In GL.iNET GL-AR300M routers with firmware v3.216, it is possible to inject arbitrary shell commands through the OpenVPN client file upload functionality.

## Remediation
Update GL.iNet GL-AR300M router firmware to the latest version.

## Reference
[https://nvd.nist.gov/vuln/detail/CVE-2023-46456](https://nvd.nist.gov/vuln/detail/CVE-2023-46456)