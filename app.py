from fastapi import FastAPI, Request, Form, status, Depends, HTTPException, Response, Cookie
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from pymongo import MongoClient
from passlib.context import CryptContext
from datetime import datetime, timedelta
import requests
import os
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import jwt
from jwt.exceptions import PyJWTError
import logging
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel, SecuritySchemeType
from fastapi.openapi.utils import get_openapi
from jose import JWTError, jwt

# Load environment variables from .env file
load_dotenv()
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
raw_expire_minutes = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10")
print(f"DEBUG: Raw value from os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'): '{raw_expire_minutes}'")

ACCESS_TOKEN_EXPIRE_MINUTES = int(raw_expire_minutes)

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

# Hardcoded values for demonstration; ideally, these should also come from environment variables.
# ACCESS_TOKEN_EXPIRE_MINUTES=10 # This will be overridden by the .env value if set
MONGO_URI = os.getenv("MONGO_URI")
RECAPTCHA_SITE_KEY="6Lca5TArAAAAADRedne525SsKt5jf-252ADg2uBS"
RECAPTCHA_SECRET_KEY="6Lca5TArAAAAAK2-XxkeJ1sOcIbu__yFhgBU4JWM"

if not all([SECRET_KEY, ALGORITHM, RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY, MONGO_URI]):
    raise ValueError("Missing critical environment variables. Check your .env file and ensure JWT_SECRET_KEY, JWT_ALGORITHM, and MONGO_URI are set.")

# Initialize app
app = FastAPI()

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Session middleware (kept for existing functionality that relies on it, though JWT will handle core auth)
app.add_middleware(SessionMiddleware, secret_key=os.urandom(24))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB connection
MONGO_URI = "mongodb+srv://Keerthi24:Keerthi123@keerthi1233.d7234zj.mongodb.net/?retryWrites=true&w=majority&appName=Keerthi1233"
client = MongoClient(MONGO_URI)
db = client["SCMLiteDB"]
users_collection = db["user"]
logins_collection = db["logins"]
shipment_collection = db["shipments"]
collection = db['sensor_data_collection']

# --- JWT Utility Functions ---

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except PyJWTError:
        return None # Token is invalid or expired

# Dependency to get current user from JWT token
async def get_current_user_from_token(request: Request):
    # Try to get token from header first (for API calls)
    authorization: str = request.headers.get("Authorization")
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]

    # If not in header, try from session (for traditional web app flow)
    if not token:
        token = request.session.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if payload is None:
        request.session.pop("username", None) # Clear session if token invalid
        request.session.pop("role", None)
        request.session.pop("access_token", None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = users_collection.find_one({"email": email})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

# Dependency to check if user is an admin
async def get_current_admin_user(current_user: dict = Depends(get_current_user_from_token)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have enough privileges",
        )
    return current_user

# ---------------------------
# GLOBAL ERROR HANDLERS
# ---------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # For HTML responses, redirect to login with a flash message
    if request.headers.get("accept", "").startswith("text/html"):
        request.session["flash"] = exc.detail
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse({"detail": exc.errors()}, status_code=400)

# --- Logging Configuration ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('app.log')
stream_handler = logging.StreamHandler()

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# --- OAuth2 Configuration ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
def root():
    logger.info('Root endpoint accessed')
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse, name="login")
def get_login(request: Request):
    logger.info('Login endpoint accessed')
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("login.html", {"request": request, "site_key": RECAPTCHA_SITE_KEY, "flash": flash})

@app.get("/signup", response_class=HTMLResponse, name="signup")
def get_signup(request: Request):
    logger.info('Signup endpoint accessed')
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("signup.html", {"request": request, "flash": flash})

@app.post("/signup")
def post_signup(
    request: Request,
    fullname: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form("user") # Default to 'user' if not provided
):
    logger.info('Signup form submitted')
    if password != confirm_password:
        request.session["flash"] = "Passwords do not match."
        logger.warning('Passwords do not match')
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if users_collection.find_one({"email": email}):
        request.session["flash"] = "Email already registered."
        logger.warning('Email already registered')
        return RedirectResponse(url="/signup", status_code=status.HTTP_302_FOUND)

    if role not in ["user", "admin"]:
        role = "user" # Ensure only valid roles are assigned

    password_hash = pwd_context.hash(password)
    users_collection.insert_one({
        "name": fullname,
        "email": email,
        "password_hash": password_hash,
        "role": role,
        "created_at": datetime.utcnow()
    })

    request.session["flash"] = "Account created successfully! Please log in."
    logger.info('Account created successfully')
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.post("/login")
async def post_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(alias="g-recaptcha-response")
):
    logger.info('Login form submitted')
    recaptcha_verify = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": RECAPTCHA_SECRET_KEY, "response": g_recaptcha_response}
    )
    result = recaptcha_verify.json()

    if not result.get("success"):
        request.session["flash"] = "reCAPTCHA failed. Try again."
        logger.warning('reCAPTCHA failed')
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user = users_collection.find_one({"email": username})
    if user and pwd_context.verify(password, user["password_hash"]):
        # Create JWT token
        access_token = create_access_token(data={"sub": user["email"], "role": user.get("role", "user")})

        # Store token in session (for web app flow)
        request.session["access_token"] = access_token
        request.session["username"] = username # Keep for existing templates that might use it directly
        request.session["role"] = user.get("role", "user") # Keep for existing templates

        logins_collection.insert_one({
            "email": username,
            "login_time": datetime.utcnow(),
            "status": "success"
        })

        logger.info('Login successful')
        if user.get("role") == "admin":
            return RedirectResponse(url="/admin-dashboard", status_code=status.HTTP_302_FOUND)
        else:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

    logins_collection.insert_one({
        "email": username,
        "login_time": datetime.utcnow(),
        "status": "failed"
    })
    request.session["flash"] = "Invalid credentials."
    logger.warning('Invalid credentials')
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f'Dashboard endpoint accessed by {current_user.get("email")}')
    # The current_user dependency already handles authentication and redirection
    # if not authenticated.
    return templates.TemplateResponse("dashboard.html", {"request": request, "name": current_user.get("name")})

@app.get("/admin-dashboard", response_class=HTMLResponse)
def get_admin_dashboard(request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f'Admin dashboard endpoint accessed by {current_user.get("email")}')
    # The get_current_admin_user dependency already handles authentication and role check.
    return templates.TemplateResponse("admin_dashboard.html", {"request": request, "name": current_user.get("name")})

@app.get("/create-shipment", response_class=HTMLResponse)
def get_create_shipment(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f'Create shipment endpoint accessed by {current_user.get("email")}')
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse("create_shipment.html", {
        "request": request,
        "user_name": current_user.get("name"),
        "flash": flash
    })

@app.post("/create-shipment", response_class=HTMLResponse)
async def create_shipment(
    request: Request,
    current_user: dict = Depends(get_current_user_from_token), # Protect this route
    shipment_id: str = Form(...),
    po_number: str = Form(...),
    route_details: str = Form(...),
    device: str = Form(...),
    ndc_number: str = Form(...),
    serial_number: str = Form(...),
    container_number: str = Form(...),
    goods_type: str = Form(...),
    expected_delivery_date: str = Form(...),
    delivery_number: str = Form(...),
    batch_id: str = Form(...),
    origin: str = Form(...),
    destination: str = Form(...),
    status: str = Form(...),
    shipment_description: str = Form(...)
):
    logger.info(f'Shipment creation form submitted by {current_user.get("email")}')
    shipment = {
        "shipment_id": shipment_id,
        "po_number": po_number,
        "route_details": route_details,
        "device": device,
        "ndc_number": ndc_number,
        "serial_number": serial_number,
        "container_number": container_number,
        "goods_type": goods_type,
        "expected_delivery_date": expected_delivery_date,
        "delivery_number": delivery_number,
        "batch_id": batch_id,
        "origin": origin,
        "destination": destination,
        "status": status,
        "shipment_description": shipment_description,
        "created_at": datetime.utcnow()
    }

    try:
        shipment_collection.insert_one(shipment)
        flash_message = f"Shipment {shipment_id} created successfully!"
        logger.info(f"Shipment {shipment_id} created by {current_user.get('email')}")
    except Exception as e:
        print(f"Database error: {e}")
        flash_message = f"Error creating shipment: {str(e)}"
        logger.error(f"Error creating shipment by {current_user.get('email')}: {e}")

    return templates.TemplateResponse("create_shipment.html", {"request": request, "flash": flash_message})

@app.get("/user_management", response_class=HTMLResponse)
def user_management(request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f'User management endpoint accessed by {current_user.get("email")}')
    users = list(users_collection.find({}, {"_id": 0, "name": 1, "email": 1, "role": 1}))
    return templates.TemplateResponse("user_management.html", {"request": request, "users": users})
@app.get("/edit_user/{email}", response_class=HTMLResponse)
async def edit_user(email: str, request: Request):
    user = users_collection.find_one({"email": email})
    if not user:
        return HTMLResponse("User not found", status_code=404)
    return templates.TemplateResponse("edit_users.html", {"request": request, "user": user})

@app.get("/edit-users/{email}", response_class=HTMLResponse)
async def get_edit_user(request: Request, email: str, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f'Edit user endpoint accessed for {email} by {current_user.get("email")}')

    user = users_collection.find_one({"email": email})
    print(user)
    flash = request.session.pop("flash", None)

    if not user:
        request.session["flash"] = "User not found."
        logger.warning(f"User {email} not found for editing by {current_user.get('email')}")
        return RedirectResponse(url="/user_management", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse("edit_user.html", {
        "request": request,
        "user": user,
        "flash": flash
    })
@app.post("/update-user/{email}")
async def update_user(
    request: Request,
    email: str,
    name: str = Form(...),
    new_email: str = Form(...),
    role: str = Form(...),
    current_user: dict = Depends(get_current_admin_user)
):
    logger.info(f'Update user form submitted for {email} by {current_user.get("email")}')
    result = users_collection.update_one(
        {"email": email},
        {"$set": {"name": name, "email": new_email, "role": role}}
    )
    if result.modified_count == 1:
        request.session["flash"] = "User updated successfully."
        logger.info(f"User {email} updated successfully by {current_user.get('email')}")
    else:
        request.session["flash"] = "No changes made or user not found."
        logger.warning(f"No changes made or user {email} not found during update by {current_user.get('email')}")
    return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

@app.get("/delete-user/{email}")
def delete_user(email: str, request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f'Delete user endpoint accessed for {email} by {current_user.get("email")}')
    users_collection.delete_one({"email": email})
    request.session["flash"] = "User deleted."
    logger.info(f"User {email} deleted by {current_user.get('email')}")
    return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

@app.get("/assign-admin/{email}")
def assign_admin(email: str, request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f'Assign admin endpoint accessed for {email} by {current_user.get("email")}')
    user = users_collection.find_one({"email": email})
    if not user:
        request.session["flash"] = "User not found."
        logger.warning(f"User {email} not found for admin assignment by {current_user.get('email')}")
        return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)
    result = users_collection.update_one({"email": email}, {"$set": {"role": "admin"}})
    if result.modified_count == 1:
        request.session["flash"] = f"{email} is now an admin."
        logger.info(f"{email} assigned admin role by {current_user.get('email')}")
    else:
        request.session["flash"] = "No changes made or user already admin."
        logger.warning(f"No changes made or user {email} already admin during assignment by {current_user.get('email')}")
    return RedirectResponse("/user_management", status_code=status.HTTP_302_FOUND)

@app.get("/edit-shipment", response_class=HTMLResponse)
def get_edit_shipment(request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f'Edit shipment endpoint accessed by {current_user.get("email")}')
    flash = request.session.pop("flash", None)
    shipments = list(shipment_collection.find({}, {"_id": 0}))
    return templates.TemplateResponse("edit_shipment.html", {
        "request": request,
        "shipments": shipments,
        "flash": flash
    })

@app.post("/edit-shipment")
def post_edit_shipment(
    request: Request,
    current_user: dict = Depends(get_current_admin_user), # Protect this route
    shipment_id: str = Form(...),
    status_update: str = Form(..., alias="status"), # Renamed to avoid conflict with `status` from fastapi
    destination: str = Form(...),
    expected_delivery_date: str = Form(...)
):
    logger.info(f'Edit shipment form submitted for {shipment_id} by {current_user.get("email")}')
    result = shipment_collection.update_one(
        {"shipment_id": shipment_id},
        {"$set": {
            "status": status_update,
            "destination": destination,
            "expected_delivery_date": expected_delivery_date,
            "last_updated": datetime.utcnow()
        }}
    )
    if result.modified_count > 0:
        request.session["flash"] = "Shipment updated successfully."
        logger.info(f"Shipment {shipment_id} updated by {current_user.get('email')}")
    else:
        request.session["flash"] = "No changes made or shipment not found."
        logger.warning(f"No changes made or shipment {shipment_id} not found during update by {current_user.get('email')}")
    return RedirectResponse(url="/edit-shipment", status_code=status.HTTP_302_FOUND)

@app.get("/delete-shipment/{shipment_id}")
def delete_shipment(shipment_id: str, request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.info(f'Delete shipment endpoint accessed for {shipment_id} by {current_user.get("email")}')
    result = shipment_collection.delete_one({"shipment_id": shipment_id})
    if result.deleted_count > 0:
        request.session["flash"] = "Shipment deleted successfully."
        logger.info(f"Shipment {shipment_id} deleted by {current_user.get('email')}")
    else:
        request.session["flash"] = "Shipment not found or already deleted."
        logger.warning(f"Shipment {shipment_id} not found or already deleted during deletion by {current_user.get('email')}")
    return RedirectResponse(url="/edit-shipment", status_code=status.HTTP_302_FOUND)

@app.get("/all-shipments", response_class=HTMLResponse)
def get_all_shipments(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f'All shipments endpoint accessed by {current_user.get("email")}')
    shipments = list(shipment_collection.find({}, {"_id": 0}))
    return templates.TemplateResponse("all_shipments.html", {"request": request, "shipments": shipments, "role": current_user.get("role")})

@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f'Account page accessed by {current_user.get("email")}')
    # The current_user dependency ensures the user is authenticated.
    return templates.TemplateResponse("account.html", {"request": request, "user": current_user})

@app.get("/device-data", response_class=HTMLResponse)
async def device_data(request: Request, current_user: dict = Depends(get_current_user_from_token)):
    logger.info(f'Device data endpoint accessed by {current_user.get("email")}')
    data = list(collection.find().sort([('_id', -1)]).limit(10))
    # Convert ObjectId to string
    formatted_data = []
    for item in data:
        item['_id'] = str(item['_id'])
        formatted_data.append(item)
    return templates.TemplateResponse("device_data.html", {
        "request": request,
        "data": formatted_data
    })

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Replace with your user validation logic
    if form_data.username != "user" or form_data.password != "pass":
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": form_data.username})
    response = JSONResponse(content={"access_token": access_token, "token_type": "bearer"})
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.post("/logout")
def logout(response: Response):
    response = JSONResponse(content={"msg": "Logged out"})
    response.delete_cookie(key="access_token")
    return response

@app.get("/protected")
def protected(token: str = Depends(oauth2_scheme)):
    verify_token(token)
    return {"msg": "You are authorized"}

# Custom OpenAPI to add the lock icon and bearer auth in Swagger UI
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Your API",
        version="1.0.0",
        description="API with OAuth2 Bearer and Swagger UI lock icon",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    for path in openapi_schema["paths"].values():
        for op in path.values():
            op["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.get("/logout")
def logout(request: Request):
    logger.info('Logout endpoint accessed')
    request.session.clear() # Clear all session data, including the JWT
    request.session["flash"] = "Logged out successfully."
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)





















