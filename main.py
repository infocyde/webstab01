from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import jwt, time


SECRET = "hardcodedsecret01" #todo: change this
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
def root(request:Request,user=Depends(require_user)):
    return templates.TemplateResponse("main.html",{"request":request,"user":user})




@app.get("/login", response_class=HTMLResponse)
def login_page(request:Request):
    return templates.TemplateResponse("login_form.html",{"request":request})




@app.post("/login", response_class=HTMLResponse)
def login(response:Response, username:str=Form(...), password:str=Form(...)):
    # hardcoded check
    if not(username=="admin" and password=="pass"):
        return HTMLResponse("Bad creds",401)
    tok = make_jwt(username)
    response.set_cookie(COOKIE,tok,httponly=True,max_age=TTL)
    return HTMLResponse("OK")