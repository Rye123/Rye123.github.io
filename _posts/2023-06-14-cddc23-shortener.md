---
title: CDDC23 - Shortener
date: 2023-06-14 21:52:09 +0800
categories: [cybersecurity]
tags: [python, ctf]
pin: false
comments: false
math: false
---

I recently participated in the [Cyber Defenders Discovery Camp (CDDC2023)](https://www.dsta.gov.sg/brainhack), and there was a particularly interesting problem I've decided to do a write-up about.
- A small disclaimer -- I had to eventually use the given hint, which simply mentioned CVE-2023-24329.

## The Problem
### Identifying the Problem
The brief provided both a download link to a `zip` folder, and a website.

Unzipping the downloaded folder, we had the following:
```
- app/
	- queries/
	- routers/
	- utils/
	- __init__.py
	- config.py
	- main.py
- dbschema/
- .env.example
- requirements.txt
- build.sh
- run.sh
- docker-compose.yml
- Dockerfile
- edgedb.toml
- flag
- README.md
```

Following the instructions in `README.md`, this created two Docker containers -- one hosted an [EdgeDB](https://www.edgedb.com/) instance, another a [FastAPI](https://fastapi.tiangolo.com/) webserver. Presumably, there was a similar setup on the given website.

Here are the important bits from the Docker composition of the containers.

> **`build.sh`**
> ```bash
> docker-compose build --build-arg SECRET="$(openssl rand -hex 16)"
> ```

> **`Dockerfile`**
> ```dockerfile
> FROM python:3.10-slim
> 
> WORKDIR /code
> COPY requirements.txt .
> 
> RUN pip install --no-cache-dir --upgrade -r requirements.txt
> COPY ./app /code/app
> COPY ./dbschema /code/dbschema
> COPY .env .
> ARG SECRET
> ENV SECRET=$SECRET
> RUN mkdir -p $SECRET
> RUN ls
> COPY flag $SECRET/
> CMD ["uvicorn", "app.main:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]
> ```

`build.sh` generates a [randomly-generated](https://www.openssl.org/docs/man1.1.1/man1/rand.html) 32-byte hexadecimal string, storing it as a build argument `SECRET`. Later, `Dockerfile` makes `SECRET` an environment variable, and copies the flag in the host machine to `/code/{SECRET}`.
- Also note that `.env` would be the `.env.example` file from the host machine, in retrospect it isn't really relevant for the solution. It contains a `SECRET_KEY` (not to be confused with `SECRET`!) and an `ALGORITHM` to be used for the generation of [JSON Web Tokens (JWT)](https://jwt.io/).

The FastAPI container would hence have the following structure:
```
- /code/
	- app/
		- queries/
		- routers/
		- utils/
		- __init__.py
		- config.py
		- main.py
	- dbschema/
	- {SECRET}/
		- flag
	- .env
- /bin
- ...(other usual root directories)...
```

The given website above would be on a similar container, having a similar file structure. The aim was hence to:
1. Use the FastAPI routes provided under `app/routers/` and perform **directory traversal**.
2. Obtain the **environment variable** `SECRET`.
3. Using step (1.), traverse to `/code/{SECRET}` and obtain `flag`.

### FastAPI Routes
The FastAPI container had several routes.

`auth.py` and `users.py` gave routes for **authentication** and **registration**.
- Essentially, the authentication route (`POST /token`) would, upon being given appropriate credentials matching a given record in the EdgeDB container, return a **JWT** as a [bearer authentication scheme](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#authentication_schemes). Subsequent requests would have that token to save the 'logged-in' status of the user.
- The registration route (`POST /users`) would store the given user and the user's hashed password in the EdgeDB container.

Of far more interest were the main application routes under `links.py`. As can be assumed from the challenge title, the program acted as a link shortener.
- Notably, all the routes required **authentication**, but didn't seem to require any special permissions.
- Hence, as long as we could create a user and log in, that would be sufficient authentication to utilise the routes here.

#### Link Creation
```python
@router.post("/links", status_code=HTTPStatus.CREATED)
async def post_link(link: RequestData, current_user, client: edgedb.AsyncIOClient) -> create_links_qry.CreateLinkResult:
    if not validLink(link.url):
        return False
    try:
        created_link = await create_links_qry.create_link(client, url=link.url, shorten=genRandomKey(), name=current_user.name)
    except:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,)
    return created_link
```

This code first **validated** a given URL, shortened it, and stored it with the user that created the link.
- Of particular interest is the `validLink()` function. As long as whatever we give it gets through, we can effectively store a URL inside.

#### Link Retrieval
```python
@router.get("/links/{shorten}")
async def get_links(shorten, current_user, client: edgedb.AsyncIOClient, preview: bool) -> ResponseData | None :
    if not shorten:
        return False
    if not current_user.name:
        return False
    try:
        link = await get_link_by_shorten_qry.get_link_by_shorten(client, shorten=shorten)
    except:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
        )
    if not link:
        raise HTTPException(status_code=404, detail="not found")
    if link.user.name != current_user.name:
        raise HTTPException(status_code=404, detail="not found")
    
    if preview:
        return ResponseData(preview=getResponse(link.url))
    else:
        return RedirectResponse(link.url)
```

This code **retrieved** a given URL from the EdgeDB container. What is particularly interesting here is the `preview` Boolean. If `false`, the code simply *redirected* you to the link's URL. Otherwise, it called `getResponse`.

### Functions of Interest
#### `getResponse(link)`
```python
def getResponse(link, length=4096)->str:
    try:
        target = urllib.request.urlopen(link, timeout=1)
        content = target.read(length)
        if not content:
            return ""
        return content
    except:
        return ""
```
-  Python's [`urlopen`](https://docs.python.org/3/library/urllib.request.html#urllib.request.urlopen) accepts schemes of the following type: `http`, `https`, `ftp`, `file`, `data`.
- **If we could give a `file://localhost/` URL, we can perform directory traversal**.
	- `file://localhost/` would give us the **root directory**. Then, assuming we knew `SECRET` from above, we would use `file://localhost/code/{SECRET}/flag` to get the flag.
	- However, we see an attempt to prevent this with the next function.

#### `validLink(link)`
```python
def validLink(link)->bool:
    if len(link) < 12: return False
	
     # Performs a series of regex checks on link
    if not isScheme(link): return False
    
    scheme, host = urlparse(link).scheme, urlparse(link).hostname
    
    # Calls socket.gethostbyname(host), returning False if it matches "127.0.0.1" or "0.0.0.0". If socket.gethostbyname(host) results in an Exception, returns False.
    if not sanityLocalHost(host): return False
	
    # Returns False if scheme is "file", "gopher", "ftp", "glob" or "data"
    if not sanitySchemes(scheme): return False
    
    # Returns False if "google.com", "bing.com", "duckduckgo.com"
    if not sanityHostName(host): return False 
    
    # Rejects any link with "127." or "localhost" inside
    if not sanityKnownBlacklist(link): return False 
    
    # Rejects a link that doesn't have a response
    if not getResponse(link, length=10): return False
    return True
```

This prevents naïve attacks like the ones mentioned above. Any `file://` scheme is rejected, and any mention of `localhost` and `127.0.0.1` are rejected.

### Sending Requests
To use the above routes, I'd initially manually crafted each request through Firefox's Network tab, until I realised that [FastAPI served a `/docs` route by default](https://fastapi.tiangolo.com/tutorial/metadata/#docs-urls). That made the attempts *significantly* easier.

## Initial Attempts
Prior to relenting and using the hint, I'd attempted to attack `validLink()`. By adding `print` messages below each `if` branch, I could know roughly which check the payload link failed.

I owned a domain at `rye123.net` (there's nothing there as of the time of writing). By adding an [`A` record](https://www.cloudflare.com/learning/dns/dns-records/dns-a-record/) that led to `127.0.0.1`, I could effectively break `sanityKnownBlacklist()` since the domain name didn't have `127.` or `localhost` inside.
- However, this failed against `sanityLocalHost`.
- [`gethostbyname`](https://docs.python.org/3/library/socket.html#socket.gethostbyname) calls the [system call of the same name](https://man7.org/linux/man-pages/man3/gethostbyname.3.html). From what I understand, it does a DNS lookup of the hostname and resolves to get the IP.
- Since `socket.gethostname("rye123.net")` would return `127.0.0.1` (due to the `A` record), `sanityLocalHost()` would return `False`.

I attempted several other options [here](https://brightsec.com/blog/ssrf-server-side-request-forgery/#ssrf-bypass):
- Using `127.0.1.1` would fail, because of `sanityKnownBlacklist()`.
- `http://0` and `http://0177.0.0.1` would fail, because of the comprehensive regex in `isScheme()`.
- In these attempts, [Regex101](http://regex101.com) proved *very* useful, especially since it could parse regex in Python.


## CVE-2023-24329
### Blank Spaces
Using the hint, we got a simple message informing us about **CVE-2023-24329**. Googling for it, I came across a [proof of concept](https://pointernull.com/security/python-url-parse-problem.html) of the CVE.

In Python 3.10 (the version of Python used in the container!), `urllib.parse.urlparse()` and `urllib.request.urlopen()` behaved differently.
- By default, `urlparse()` would split a given URL into its hostname, scheme, query and so on.
- For instance, `urlparse("http://www.google.com")` would be split into `scheme="http"`, `hostname="www.google.com"`.
- At the same time, `urlopen()` would actually open the URL.

However, at least prior to Python 3.10.12, blank characters were stripped from `urlopen()`, but not `urlparse()`.
- This allows for `urlparse(" http://www.google.com")` to return `scheme="", hostname="http://www.google.com"`, while still allowing `urlopen()` to open the URL.
- Since many of the blocklist checks of `validLink()` check the `scheme`, we could potentially bypass that by adding a space.

This did not seem to work, however. The version of Python 3.10 used by the Docker image appeared to already have the vulnerability patched out.

### Wrapped URLs
However, while experimenting with the URL, I did find out that using angle brackets had a similar effect.
- This was because of [Appendix C in RFC3986](https://www.rfc-editor.org/rfc/rfc3986#appendix-C), which allowed for *wrapped URLs* -- URIs that were wrapped by angle brackets (e.g. `<http://example.com>`).
- Apparently, while `urlopen()` accounted for that, `urlparse()` did not.

```python
>>> from urllib.parse import urlparse
>>> urlparse("http://www.google.com")
ParseResult(scheme='http', netloc='www.google.com', path='', params='', query='', fragment='')
>>> urlparse("<http://www.google.com>")
ParseResult(scheme='', netloc='', path='<http://www.google.com>', params='', query='', fragment='')
```

Here, using `urlparse()`, surrounding the URI with angle brackets results in an erroneous parsing of the URI.
- `scheme` becomes `''`, while `path` gets the full URI.

On the other hand, `urlopen()` handles it as expected, as `urlopen()` does a call to `urllib.parse.unwrap()` before running:
```python
>>> from urllib.request import urlopen
>>> urlopen("http://www.google.com")
<http.client.HTTPResponse object at 0x7fefd991f700>
>>> urlopen("<http://www.google.com>")
<http.client.HTTPResponse object at 0x7fefd9a7db70>
```

Going back to the relevant part of the validation code from `validLink()`, we have:
```python
scheme, host = urlparse(link).scheme, urlparse(link).hostname

# Calls socket.gethostbyname(host), returning False if it matches "127.0.0.1" or "0.0.0.0". If socket.gethostbyname(host) results in an Exception, returns True.
if not sanityLocalHost(host): return False

# Returns False if scheme is "file", "gopher", "ftp", "glob" or "data"
if not sanitySchemes(scheme): return False

# Returns False if "google.com", "bing.com", "duckduckgo.com"
if not sanityHostName(host): return False
```

With the above CVE, by surrounding our URI with angle brackets (i.e. `<http://rye123.net>`), `urlparse` would give `scheme = ''`, `host = <http://rye123.net>`.
- `socket.gethostbyname("<http://rye123.net>")` results in a `socket.gaierror` due to the angle brackets, causing `sanityLocalHost()` to return `True`.
- `sanitySchemes('')` is given an empty string, and hence returns `True`.
- Since the host obviously doesn't match the given domain names, `sanityHostName()` returns `True`.

On the other hand, on `getResponse(link)`, **`urlopen()` will still work as expected**, allowing us to effectively store `http://rye123.net` which resolves to `http://127.0.0.1`.

## Directory Traversal
### Testing our Hypothesis
We first test the above hypothesis by attempting to obtain `/code/.env`. 

Registering a user and authenticating as required, we `POST` to `/links` as shown:    
![](/assets/img/blog/cddc23-shortener/cddc23-shortener-img1.png)

We successfully obtain the following response, indicating that we've successfully gotten through `validLink()`:    
![](/assets/img/blog/cddc23-shortener/cddc23-shortener-img2.png)


Using the shortened link and **previewing it**:    
![](/assets/img/blog/cddc23-shortener/cddc-23-shortener-img3.png)

We get the following response, indicating we can successfully read the file!    
![](/assets/img/blog/cddc23-shortener/cddc-23-shortener-img4.png)

Of course, we're not done. We **want to get `/code/{SECRET}/flag`**, but we **don't know what `SECRET` is**.

### Obtaining Environment Variables
I went on a little wild goose chase, trying to find out how I could perform remote code execution on the system to attempt to get the environment variables. It proved unnecessary, as eventually, I came across [this link about Docker environment variables](https://www.linkedin.com/pulse/stop-passing-secrets-via-environment-variables-your-huerta).

Essentially, I could obtain the *initial* environment variables of a process of ID `pid` by accessing `/proc/{pid}/environ`. And since we call `ENV SECRET=$SECRET` in the `Dockerfile` above, we know that the `SECRET` environment variable should be in the **init process**'s environment variables. That is, we can get the `SECRET` environment variable by accessing `/proc/1/environ`.

Again with the same procedure as above, we successfully shorten the link `<file://rye123.net/proc/1/environ>`. Retrieving the shortened link with a preview, we've managed to obtain *all* the environment variables:    
![](/assets/img/blog/cddc23-shortener/cddc-23-shortener-img5.png)

In this case, the randomly generated secret is `5281ccd90d91de295c3940720f9c890b`.

Obtaining the flag is simply repeating the same process for `<file://rye123.net/code/5281ccd90d91de295c3940720f9c890b/flag>`. Again, retrieving the link, we get:    
![](/assets/img/blog/cddc23-shortener/cddc-23-shortener-img6.png)

## Retrospective
Looking at the flag now, I think I was supposed to do something along the lines of adding a black space to the front of the URL, as the proof-of-concept did. Perhaps the Python version used by the CDDC-hosted website was the unpatched one, which would allow the blank space exploit to work on it even though it didn't work on my local copy (since the `Dockerfile` would pull the presumably-patched version of `python3.10-slim`).

In terms of defence, the [`urllib.parse` documentation](https://docs.python.org/3/library/urllib.parse.html#url-parsing-security) suggests that output from `urlparse` should not be fully trusted, as exceptions may not be raised from unexpected input. Proper validation should be done on the output where necessary.
