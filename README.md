# Spectre
a small python tool for web vulnerability hunting, leveraging HTTPX, Selenium and Beautifulsoup4.

This was a project i created out of nesesscity for bug bounty hunting, among other things.

This should be able to integrate with the wrapper scripts I've created for some of project.io's tools such as katana/subfinder.


# Arguments:

``
usage: main.py [-h] [--urls URLS [URLS ...]] --vuln {xss,csrf,sqli,csp,all} [--proxy PROXY] [--log-level {debug,info,warning}] [--payload-type {basic,advanced,polyglot}] [--delay DELAY] [--interactive]
``

### Argument Breakdown

```
-h                       | Shows a help message and then quits

--urls                   | used to specify a list of url's from a text file 

--vuln                   | used to specify the vulnerability type to scan for: {xss, csrf, sqli, csp, all}

--payload-type           | select payload type from one of 3 types: {basic, advanced, polyglot}

--proxy                  | defaults to http://127.0.0.1:8080 to integrate with burpsuite's proxy

--delay                  | used to enforce a client rate limit

--interactive            | can be used to manually verify if a URL has vulnerable content, however this is mostly used for debugging

--log-level              | multiple option argument, used to declare log verbosity, default value is {info}: {info, warning, debug}
```

# Functionality
By default Spectre takes screenshots of all webpages it encounters, as well as checks for DOM-based verification on payload execution (XSS mainly)

Leveraging HTTPX we're able to create session persistence client side via a cookie jar. This is also useful for bypassing the need to login per request, i'll look to be adding a function to pull credentials from a CLI argument.

So far i've got the capabilities for the following
```
Payloads
----------------------------------------------------------------------------------------------------------------------------------------
XSS Testing - executes and analyzes the web page to verify if our specified XSS payload executed correctly.
CSRF Testing - runs tests for CSRF vulnerabilities.
SQLi Testing - will run various SQLi payloads and analyze the response header for any indication of a wrongly configured SQL server.
CSP Analysis - runs an analysis on the Content-Security-Policies present in the response headers and looks for wrongly configured CSP's.


Payload Functions
----------------------------------------------------------------------------------------------------------------------------------------
Payload Encoding - Supports URL, hex & base64 for payload encoding.
Payload Mutation - Applies various mutations to payloads before sending them.


HTTP Client
----------------------------------------------------------------------------------------------------------------------------------------
Custom User-Agents - rotates through a list of 1000 random user agents.
Rate Limiting Detection - handles and respects rate limits from the server.
Proxy Support - local proxy support to route all traffic through a proxy of your choice (default is 127.0.0.1:8080)
Traffic Logging - logs all inbound and outbound traffic to and from specified URL's for analysis.
Request Replay - allows for replaying of previous events.


CLI
----------------------------------------------------------------------------------------------------------------------------------------
Dynamic URL Testing - Accepts a list of URL's to run through, recommended to use output from Katana.
Vulnerability Type Selection - Ability to choose various vulnerabilities to test for.
Payload Type Selection - Ability to choose various payload types to test with.
Delay Management - Sets a delay between requests to manage traffic and avoid blacklisting (Default is 5 seconds)


Additional Features
----------------------------------------------------------------------------------------------------------------------------------------
Custom HTTP Headers - Support for custom HTTP headers, useful for bug bounties to differentiate your traffic from legit traffic.
Session Management - Ability to maintain and manage session cookies across requests


