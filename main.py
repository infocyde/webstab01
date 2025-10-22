from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException, Response as RawResponse
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
import jwt, time


SECRET = "hardcodedsecret02" #todo: change this
ALGO = "HS256"
TTL = 60*60*24
COOKIE = "access_token"


app = FastAPI()
templates = Jinja2Templates("templates")


# ---- JWT helpers ----
def make_jwt(sub: str):
    now = int(time.time())
    return jwt.encode({
    "sub": sub,
    "iat": now,
    "exp": now+TTL
    }, SECRET, algorithm=ALGO)


def require_user(request: Request, response: Response):
    t = request.cookies.get(COOKIE)
    if not t: 
        raise HTTPException(401)
    try:
        p = jwt.decode(t, SECRET, algorithms=[ALGO])
    except: 
        raise HTTPException(401)
    # sliding session reissue
    new = make_jwt(p["sub"])
    response.set_cookie(COOKIE,new,httponly=True,max_age=TTL)
    return p["sub"]


# ---- pages ----

@app.get("/", response_class=HTMLResponse)
def root(request: Request, response: Response):
    token = request.cookies.get(COOKIE)

    # ---- not authenticated ----
    if not token:
        # If request is from HTMX, do HX-Redirect
        if request.headers.get("HX-Request"):
            r = RawResponse()
            r.headers["HX-Redirect"] = "/login"
            return r
        # Normal browser direct hit -> regular redirect
        return RedirectResponse("/login", status_code=302)

    # ---- try to validate and refresh sliding token ----
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO])
    except Exception:
        # treat invalid token same as not logged in
        if request.headers.get("HX-Request"):
            r = RawResponse()
            r.headers["HX-Redirect"] = "/login"
            return r
        return RedirectResponse("/login", status_code=302)

    # re-issue sliding expiration token
    new_tok = make_jwt(payload["sub"])
    response.set_cookie(COOKIE, new_tok, httponly=True, max_age=TTL)

    # ---- render protected page ----
    return templates.TemplateResponse("main.html", {
        "request": request,
        "user": payload["sub"]
    })


@app.get("/login", response_class=HTMLResponse)
def login_page(request:Request):
    return templates.TemplateResponse("login_form.html",{"request":request})


@app.post("/login")
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    # hardcoded check
    if not (username == "admin" and password == "pass"):
        return HTMLResponse("Bad creds", 401)
    
    # Create token and set cookie
    tok = make_jwt(username)
    response.set_cookie(COOKIE, tok, httponly=True, max_age=TTL)
    
    # Redirect to main page
    if request.headers.get("HX-Request"):
        # If HTMX request, use HX-Redirect header
        r = RawResponse()
        r.headers["HX-Redirect"] = "/"
        r.set_cookie(COOKIE, tok, httponly=True, max_age=TTL)
        return r
    else:
        # Regular form post, use standard redirect
        return RedirectResponse("/", status_code=303)