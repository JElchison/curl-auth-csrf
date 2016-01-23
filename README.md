# curl-auth-csrf
Python tool that mimics [cURL](http://curl.haxx.se/), but performs a login and handles any [Cross-Site Request Forgery (CSRF)](https://en.wikipedia.org/wiki/Cross-site_request_forgery) tokens.

Useful for scraping HTML normally only accessible when logged in.

## Features

* Runs on any OS supported by Python
* Allows specifying arbitrary GET/POST data to be included with login form submission (i.e. username)
* Reads password from stdin (to avoid the plain-text password showing up in shell history)
* Parses login form and dynamically replicates all form inputs (including hidden ones such as `csrfmiddlewaretoken`)
* Automatically populates [HTTP Referer](https://en.wikipedia.org/wiki/HTTP_referer) header consistent with expected login sequence
* To support multiple login forms on the page, script allows specifying HTML `id` of form
* To support multiple password fields within the same login form (though rare), script allows specifying HTML field name for password
* Allows validating login success by testing resultant URL and/or content on resultant page
* Session (cookie) management during every script run
* Allows an arbitrary number of pages to be fetched while logged in
* Optionally performs logout (to avoid leaving a session open from the server's perspective)
* Allows [User-Agent](https://en.wikipedia.org/wiki/User_agent) string spoofing (chooses a "safe" default if not otherwise specified)
* Defaults to output via stdout, but can alternatively output to file

## Usage

```
usage: curl-auth-csrf.py [-h] [-a USER_AGENT_STR] -i LOGIN_URL [-f FORM_ID]
                         [-p PASSWORD_FIELD_NAME] [-d DATA] [-u SUCCESS_URL]
                         [-t SUCCESS_TEXT] [-j LOGOUT_URL] [-o FILE]
                         [--version]
                         url_after_login [url_after_login ...]

Python tool that mimics curl, but performs a login and handles any Cross-Site
Request Forgery (CSRF) tokens.  Useful for scraping HTML normally only
accessible when logged in.

positional arguments:
  url_after_login

optional arguments:
  -a USER_AGENT_STR, --user-agent-str USER_AGENT_STR
                        User-Agent string to use
  -i LOGIN_URL, --login-url LOGIN_URL
                        URL that contains the login form
  -f FORM_ID, --form-id FORM_ID
                        HTML id attribute of login form
  -p PASSWORD_FIELD_NAME, --password-field-name PASSWORD_FIELD_NAME
                        name of input field containing password
  -d DATA, --data DATA  adds the specified data to the form submission
                        (usually just the username)
  -u SUCCESS_URL, --success-url SUCCESS_URL
                        URL substring constituting successful login
  -t SUCCESS_TEXT, --success-text SUCCESS_TEXT
                        HTML snippet constituting successful login
  -j LOGOUT_URL, --logout-url LOGOUT_URL
                        URL to be visited to perform the logout
  -o FILE, --output FILE
                        write output to <file> instead of stdout
  --version             show program's version number and exit
  -h, --help            show this help message and exit

Actual password should be passed in via stdin.
```

### Password Entry

The script expects the password to be passed in via stdin, to avoid the plain-text password showing up in shell history.  A simple way to do this is as follows:

```
echo -n ThisIsMyPassword | ./curl-auth-csrf.py -i http://foobar.com/login -d username=bob http://foobar.com/secure_page
```

Note the `-n` to avoid a spurious newline after the password.

However, this defeats the purpose, as the password still shows up in the shell history.  (Exception: In Bash, start the line with an initial space, which will prevent the line from showing up in the history.  Refer to [Bash documentation](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html) on HISTCONTROL and HISTIGNORE.)

A better way to handle this is with a CLI password management tool, such as [pass](http://www.passwordstore.org/).  This is the recommended approach.  For example:

```
pass foobar.com | tr '\n' 'x' | sed 's/x$//' | ./curl-auth-csrf.py -i http://foobar.com/login -d username=bob http://foobar.com/secure_page
```

Note the calls to `tr` and `sed`, which remove the trailing newline that pass adds after the password.

## Example

If your username is `bob@email.com` for `pbs.org`, following is how you might normally scrape the zip code from your user profile:

```
curl -s https://account.pbs.org/accounts/profile/ | grep Zip
```

However, since doing so requires being logged in, here's one way to do it using curl-auth-csrf:

```
pass pbs.org/bob@email.com | tr '\n' 'x' | sed 's/x$//' | ./curl-auth-csrf.py -i https://account.pbs.org/accounts/login/ -d email=bob@email.com -u https://account.pbs.org/accounts/profile/ -j https://account.pbs.org/accounts/logout/ https://account.pbs.org/accounts/profile/ | grep Zip
```



Notes:
* The URL of the login page is `https://account.pbs.org/accounts/login/`
* The HTML input field of the username is `email`
* The URL we're taken to upon successful login is `https://account.pbs.org/accounts/profile/`
* The URL of the logout page is `https://account.pbs.org/accounts/logout/`
* The URL we want to scrap the zip code from is `https://account.pbs.org/accounts/profile/`
* The information scraped is the only data written to stdout, so we can grep over it to pull what we're looking for

## Limitations

This script will not handle the following scenarios:
* Logins involving [CAPTCHA](https://en.wikipedia.org/wiki/CAPTCHA)
* Logins involving re-authentications (i.e. multiple successive password prompts)
* Logins involving [two-factor authentication](https://en.wikipedia.org/wiki/Two-factor_authentication)
* Logins involving any client-side password transformations (i.e. passing a hashed password to the server)

## Disclaimer

Please don't abuse this tool.  Only use it with accounts that rightfully belong to you.  If you use this tool with someone else's login, you are solely responsible and may face legal consequences.

This script isn't perfect.  See the [Limitations](#Limitations) section above; also, there may be defects.  Beware that some Internet services won't take kindly if you login incorrectly (i.e. not in a normal browser).  Your using this tool means that you accept full responsibility for anything that might happen.

## Debugging

If you're having trouble finding the right parameters, you can change the default debugging level from "WARNING" to "DEBUG" at the top of the Python script.
