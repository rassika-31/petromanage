from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class LoginData(BaseModel):
    username: str
    password: str

class SignupData(BaseModel):
    username: str
    email: str
    password: str
    role: str

class InventoryItem(BaseModel):
    product_name: str
    quantity: float
    unit: str
    location: str

class TransactionData(BaseModel):
    type: str
    product_name: str
    quantity: float
    notes: str = ""

def create_token(data: dict):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")

@app.get("/")
def root():
    return {"message": "PetroManage API is running!"}

@app.post("/auth/signup")
def signup(data: SignupData):
    try:
        existing = supabase.table("users").select("*").eq("username", data.username).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Username already exists")
        pwd = data.password[:70]
        hashed = pwd_context.hash(pwd)
        result = supabase.table("users").insert({
            "username": data.username,
            "email": data.email,
            "password_hash": hashed,
            "role": data.role
        }).execute()
        return {"message": "User created successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/login")
def login(data: LoginData):
    try:
        result = supabase.table("users").select("*").eq("username", data.username).execute()
        if not result.data:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        user = result.data[0]
        pwd = data.password[:70]
        if not pwd_context.verify(pwd, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        token = create_token({"user_id": user["id"], "username": user["username"], "role": user["role"]})
        supabase.table("audit_logs").insert({
            "action": "login",
            "username": user["username"],
            "details": "User logged in"
        }).execute()
        return {"token": token, "role": user["role"], "username": user["username"]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/inventory")
def get_inventory():
    result = supabase.table("inventory").select("*").execute()
    return result.data

@app.post("/inventory")
def add_inventory(item: InventoryItem):
    result = supabase.table("inventory").insert({
        "product_name": item.product_name,
        "quantity": item.quantity,
        "unit": item.unit,
        "location": item.location
    }).execute()
    return {"message": "Item added", "data": result.data}

@app.get("/transactions")
def get_transactions():
    result = supabase.table("transactions").select("*").execute()
    return result.data

@app.post("/transactions")
def add_transaction(data: TransactionData):
    result = supabase.table("transactions").insert({
        "type": data.type,
        "product_name": data.product_name,
        "quantity": data.quantity,
        "notes": data.notes
    }).execute()
    return {"message": "Transaction recorded", "data": result.data}

@app.get("/users")
def get_users():
    result = supabase.table("users").select("id, username, email, role, created_at").execute()
    return result.data

@app.get("/audit-logs")
def get_audit_logs():
    try:
        result = supabase.table("audit_logs").select("*").order("created_at", desc=True).limit(20).execute()
        return result.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.delete("/users/{user_id}")
def delete_user(user_id: str):
    try:
        supabase.table("users").delete().eq("id", user_id).execute()
        return {"message": "User deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/inventory/{item_id}")
def delete_inventory(item_id: str):
    try:
        supabase.table("inventory").delete().eq("id", item_id).execute()
        return {"message": "Item deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/inventory/{item_id}")
def update_inventory(item_id: str, item: InventoryItem):
    try:
        result = supabase.table("inventory").update({
            "product_name": item.product_name,
            "quantity": item.quantity,
            "unit": item.unit,
            "location": item.location
        }).eq("id", item_id).execute()
        return {"message": "Item updated", "data": result.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ReportData(BaseModel):
    report_type: str
    generated_by: str
    data: dict

@app.get("/reports")
def get_reports():
    try:
        result = supabase.table("reports").select("*").order("created_at", desc=True).execute()
        return result.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/reports")
def generate_report(report: ReportData):
    try:
        result = supabase.table("reports").insert({
            "report_type": report.report_type,
            "data": report.data
        }).execute()
        return {"message": "Report generated", "data": result.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/reports/{report_id}")
def delete_report(report_id: str):
    try:
        supabase.table("reports").delete().eq("id", report_id).execute()
        return {"message": "Report deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
