---
layout: post
title:  Tiny File Manager Multiple Vulnerabilities
description: Advisory about Path Traversal Recursive Directory Listing and Arbitrary File Copy vulnerabilities found on Tiny File Manager.
date:   2020-04-28
categories: cve-advisories
share: true
tags:
 - cve-advisories
 - CVE-2020-12102
 - CVE-2020-12103
---

![Tiny File Manager logo]({{ '/assets/images/tiny-file-manager-logo.png' | relative_url }})

# Advisory Info

**CVEID:** CVE-2020-12102, CVE-2020-12103
**CVSSv3.1 Score:** 7.7 (High), 7.7 (High)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N, AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N
**Affected Products and Versions:** Tiny File Manager – 2.4.1
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura

# Executive Summary
Two security issues were found in Tiny File Manager (2.4.1).
Both vulnerabilities are exploitable only while authenticated as a non-readonly user, or while authentication is disabled.
The first one (CVE-2020-12102) is a Path Traversal Recursive Directory Listing that allows to enumerate files and directories outside the scope of the application via a Path Traversal attack.
The second one (CVE-2020-12103) is an Arbitrary File Copy that allows to create backup copies (with ".bak" extension) of files outside the scope in the same directory in which they are stored.
Both vulnerabilities are exploitable by sending a specially crafted HTTP POST request.

# Proof of Concept
As a Proof of Concept there follows a write-up in which we’re going to combine both vulnerabilities to enumerate PHP files in the webserver and view their source code in clear.

After installing Tiny File Manager locally (by cloning the repository inside `/var/www/html`), we’re going to configure the application scope to the files subfolder by editing the `$root_path` variable.

![img]({{ '/assets/images/tiny-file-manager-1.png' | relative_url }}){: .center-image }*Tiny File Manager configuration editing*

Then we’re going to create dummy files inside of it as well. As you can see in the following picture this is the application scope (`/var/www/html/files`).

![img]({{ '/assets/images/tiny-file-manager-2.png' | relative_url }}){: .center-image }*Tiny File Manager file scope*

Now in order to exploit these vulnerabilities we need to be authenticated, so we make an HTTP POST request using default credentials and we’re going to use the session cookie assigned.

![img]({{ '/assets/images/tiny-file-manager-3.png' | relative_url }}){: .center-image }*Tiny File Manager authentication request*

Once authenticated we’re going to exploit the first vulnerability by sending an HTTP POST request structured as follows:

>HTTP Request
{:.filename}
{% highlight http %}
POST /tinyfilemanager/tinyfilemanager.php?p= HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Cookie: filemanager=apak2kmrti634ncftvj6jnj6g3

ajax=1&type=search&path=../
{% endhighlight %}

Using a Path Traversal attack (by setting `../` as `path` parameter) to enumerate files and directories outside the application scope. As you can see in the following picture the attack worked: the server responded with a JSON that recursively lists all the files inside the directory one level outside the application scope, listing the content of `/var/www/html` including the Tiny File Manager PHP source file `tinyfilemanager.php`.

![img]({{ '/assets/images/tiny-file-manager-4.png' | relative_url }}){: .center-image }*Path Traversal Recursive Directory Listing*

Then in order to read its source code in clear we’re going to create a backup copy of it by sending another HTTP POST request structured as follows:

>HTTP Request
{:.filename}
{% highlight http %}
POST /tinyfilemanager/tinyfilemanager.php?p= HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 78
Cookie: filemanager=apak2kmrti634ncftvj6jnj6g3

ajax=1&type=backup&path=/var/www/html/tinyfilemanager&file=tinyfilemanager.php
{% endhighlight %}

Using absolute path on parameter `path` to bypass the application scope. As you can see in the following picture, a backup file was created as response of this request.

![img]({{ '/assets/images/tiny-file-manager-5.png' | relative_url }}){: .center-image }*Arbitrary File Copy on tinyfilemanager.php*

This file is an identical copy of the file we chose, but with a `.bak` extension, which allows us to read its content in plaintext without PHP interpreting it.
In fact, as you can see in the following picture, the content of the created `.bak` file is the source code of Tiny File Manager application in plaintext.

![img]({{ '/assets/images/tiny-file-manager-6.png' | relative_url }}){: .center-image }*Source code disclosure of tinyfilemanager.php*

So, we’ve showed how to retrieve this application’s source code by exploiting these vulnerabilities, but now we’re going to show how to retrieve other PHP files’ source code in the webserver.

![img]({{ '/assets/images/tiny-file-manager-7.png' | relative_url }}){: .center-image }*Finding other PHP files by exploiting the Path Traversal Recursive Directory Listing*

This time our target is `test90234482.php`. By accessing to it with a simple GET request, all we see is just this message.

![img]({{ '/assets/images/tiny-file-manager-8.png' | relative_url }}){: .center-image }*Accessing the test90234482.php file directly*

But by creating a backup copy and accessing to it via an HTTP GET request we can see its hidden content, normally invisible to client-side users.

![img]({{ '/assets/images/tiny-file-manager-9.png' | relative_url }}){: .center-image }*Exploiting the Arbitrary File Copy vulnerability to create a copy of test90234482.php with .bak extension*

![img]({{ '/assets/images/tiny-file-manager-10.png' | relative_url }}){: .center-image }*Accessing the copied file to read its source code in clear*

In conclusion, these two vulnerabilities if used in combination can lead to multiple issues, for instance Complete Information Disclosure by enumerating and reading potentially every PHP file in the webserver, just like we did in this write-up.

# Remediation
Update to Tiny File Manager version 2.4.2 or later.

# Timeline
27/03/2020 – Initial vendor contact
27/03/2020 – Vendor acknowledged the vulnerability
23/04/2020 – Vendor agreed to further discuss the problem and to coordinate the disclosure
14/05/2020 – Vendor publicly confirmed the issue
18/05/2020 – Vendor released a fixed version (2.4.2)

# References
[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12102](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12102)
[https://nvd.nist.gov/vuln/detail/CVE-2020-12102](https://nvd.nist.gov/vuln/detail/CVE-2020-12102)
[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12103](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12103)
[https://nvd.nist.gov/vuln/detail/CVE-2020-12103](https://nvd.nist.gov/vuln/detail/CVE-2020-12103)
[https://github.com/prasathmani/tinyfilemanager](https://github.com/prasathmani/tinyfilemanager)
[https://owasp.org/www-community/attacks/Path_Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
[https://github.com/prasathmani/tinyfilemanager/issues/357](https://github.com/prasathmani/tinyfilemanager/issues/357) (CONFIRM)
[https://github.com/prasathmani/tinyfilemanager/commit/a0c595a8e11e55a43eeaa68e1a3ce76365f29d06](https://github.com/prasathmani/tinyfilemanager/commit/a0c595a8e11e55a43eeaa68e1a3ce76365f29d06) (FIX)
[https://web.archive.org/web/20201221185237/https://www.quantumleap.it/tiny-file-manager-path-traversal-recursive-directory-listing-and-absolute-path-file-backup-copy/](https://web.archive.org/web/20201221185237/https://www.quantumleap.it/tiny-file-manager-path-traversal-recursive-directory-listing-and-absolute-path-file-backup-copy/) (Original article on archived Quantum Leap website)
[https://www2.deloitte.com/it/it/pages/risk/articles/security-advisory-article---deloitte-italy---risk1.html](https://www2.deloitte.com/it/it/pages/risk/articles/security-advisory-article---deloitte-italy---risk1.html) (Original article reupload on Deloitte website)