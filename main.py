from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException, Response as RawResponse
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
import jwt, time
from typing import Dict, Tuple


SECRET = "hardcodedsecret02" #todo: change this
ALGO = "HS256"
TTL = 60*60*24
COOKIE = "access_token"

# Brute force protection settings
MAX_ATTEMPTS = 6
LOCKOUT_DURATION = 60 * 60  # 1 hour in seconds

# In-memory storage: {ip_address: (failed_attempts, lockout_time)}
failed_logins: Dict[str, Tuple[int, float]] = {}


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


# ---- Brute force protection helpers ----
def get_client_ip(request: Request) -> str:
    """Get client IP address, accounting for proxies"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def is_locked_out(ip: str) -> bool:
    """Check if an IP is currently locked out"""
    if ip not in failed_logins:
        return False
    
    attempts, lockout_time = failed_logins[ip]
    
    # If locked out, check if lockout period has expired
    if attempts >= MAX_ATTEMPTS:
        if time.time() - lockout_time < LOCKOUT_DURATION:
            return True
        else:
            # Lockout expired, clear the record
            del failed_logins[ip]
            return False
    
    return False


def record_failed_attempt(ip: str):
    """Record a failed login attempt"""
    current_time = time.time()
    
    if ip in failed_logins:
        attempts, first_fail_time = failed_logins[ip]
        
        # If it's been more than an hour since first fail, reset counter
        if current_time - first_fail_time > LOCKOUT_DURATION:
            failed_logins[ip] = (1, current_time)
        else:
            # Increment attempts
            failed_logins[ip] = (attempts + 1, first_fail_time)
    else:
        # First failed attempt
        failed_logins[ip] = (1, current_time)


def clear_failed_attempts(ip: str):
    """Clear failed attempts on successful login"""
    if ip in failed_logins:
        del failed_logins[ip]


def get_remaining_attempts(ip: str) -> int:
    """Get number of remaining attempts before lockout"""
    if ip not in failed_logins:
        return MAX_ATTEMPTS
    
    attempts, _ = failed_logins[ip]
    return max(0, MAX_ATTEMPTS - attempts)


def get_lockout_time_remaining(ip: str) -> int:
    """Get remaining lockout time in seconds"""
    if ip not in failed_logins:
        return 0
    
    attempts, lockout_time = failed_logins[ip]
    if attempts < MAX_ATTEMPTS:
        return 0
    
    elapsed = time.time() - lockout_time
    remaining = LOCKOUT_DURATION - elapsed
    return max(0, int(remaining))


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
    client_ip = get_client_ip(request)
    
    # Check if IP is locked out
    if is_locked_out(client_ip):
        time_remaining = get_lockout_time_remaining(client_ip)
        minutes_remaining = time_remaining // 60
        return HTMLResponse(
            f"Too many failed attempts. Locked out for {minutes_remaining} more minutes.",
            status_code=429
        )
    
    # Check credentials
    if not (username == "admin" and password == "pass"):
        # Record failed attempt
        record_failed_attempt(client_ip)
        remaining = get_remaining_attempts(client_ip)
        
        if remaining > 0:
            return HTMLResponse(
                f"Bad credentials. {remaining} attempts remaining before 1-hour lockout.",
                status_code=401
            )
        else:
            return HTMLResponse(
                "Too many failed attempts. Locked out for 1 hour.",
                status_code=429
            )
    
    # Successful login - clear any failed attempts
    clear_failed_attempts(client_ip)
    
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

# note both post and get for logout
@app.get("/logout")
@app.post("/logout")
def logout(request: Request, response: Response):
    # Clear the cookie by setting max_age=0
    response.delete_cookie(COOKIE)
    
    # Redirect to login page
    if request.headers.get("HX-Request"):
        # If HTMX request, use HX-Redirect header
        r = RawResponse()
        r.headers["HX-Redirect"] = "/login"
        r.delete_cookie(COOKIE)
        return r
    else:
        # Regular request, use standard redirect
        return RedirectResponse("/login", status_code=303)


# ---- Admin/Debug endpoint (optional) ----
@app.get("/admin/failed-logins")
def view_failed_logins(username: str = Depends(require_user)):
    """View all failed login attempts - for debugging"""
    result = []
    current_time = time.time()
    
    for ip, (attempts, timestamp) in failed_logins.items():
        locked = attempts >= MAX_ATTEMPTS
        time_remaining = 0
        
        if locked:
            time_remaining = max(0, int(LOCKOUT_DURATION - (current_time - timestamp)))
        
        result.append({
            "ip": ip,
            "attempts": attempts,
            "locked_out": locked,
            "time_remaining_seconds": time_remaining
        })
    
    return {"failed_logins": result, "max_attempts": MAX_ATTEMPTS, "lockout_duration": LOCKOUT_DURATION}