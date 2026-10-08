from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import datetime
import joblib
import os

# استيراد مسار الشات بوت من مجلد chat
from chat.routes import router as chat_router

app = FastAPI(title="PhishShield AI Backend", version="1.0")

# تضمين مسار الشات بوت
app.include_router(chat_router)

# إعداد الـ CORS لربط الواجهة الأمامية بسلاسة
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- إعداد قاعدة بيانات SQLite ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./phishshield.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# تعريف جدول المستخدمين في الداتابيز
class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    date = Column(String)
    role = Column(String, default="User")

# جدول سجلات الفحص: كل فحص بيتحفظ هنا مربوط بالمستخدم (user_id)
class ScanLogModel(Base):
    __tablename__ = "scan_logs"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, index=True, nullable=False)
    element = Column(Text, nullable=False)
    scan_type = Column(String, nullable=False)      # URL / EMAIL / QR
    is_phishing = Column(Boolean, default=False)
    created_at = Column(String)                     # ISO UTC

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# دالة لإنشاء حساب الأدمن الافتراضي تلقائياً
def init_admin():
    db = SessionLocal()
    admin_user = db.query(UserModel).filter(UserModel.name == "a").first()
    if not admin_user:
        new_admin = UserModel(
            name="a",
            email="admin@phishshield.com",
            password="1",
            date=datetime.date.today().isoformat(),
            role="Admin"
        )
        db.add(new_admin)
        db.commit()
    db.close()

init_admin()

class UserRegister(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class ScanLogCreate(BaseModel):
    user_id: int
    element: str
    scan_type: str
    is_phishing: bool

class UrlInput(BaseModel):
    url: str

class EmailInput(BaseModel):
    text: str

# محرّك الفحص (موديلات + قواعد). بيتحمّل مرة واحدة عند تشغيل السيرفر
import detector

class QrInput(BaseModel):
    text: str

@app.get("/")
def read_root():
    return {"message": "PhishShield AI Backend is running successfully!"}

@app.post("/api/register")
def register_user(user: UserRegister, db: Session = Depends(get_db)):
    existing_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="البريد الإلكتروني مسجل مسبقاً!")
    
    role = "Admin" if user.name.strip() == "a" else "User"
    
    new_user = UserModel(
        name=user.name,
        email=user.email,
        password=user.password,
        date=datetime.date.today().isoformat(),
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "تم إنشاء الحساب بنجاح", "user": {"id": new_user.id, "name": new_user.name, "role": new_user.role}}

@app.post("/api/login")
def login_user(data: UserLogin, db: Session = Depends(get_db)):
    if data.username == "a" and data.password == "1":
        admin_obj = db.query(UserModel).filter(UserModel.name == "a").first()
        return {
            "message": "تم تسجيل الدخول بنجاح",
            "user": {
                "id": admin_obj.id if admin_obj else 1,
                "name": "a",
                "email": admin_obj.email if admin_obj else "admin@phishshield.com",
                "role": "Admin"
            }
        }
    
    user = db.query(UserModel).filter((UserModel.name == data.username) | (UserModel.email == data.username)).first()
    if not user or user.password != data.password:
        raise HTTPException(status_code=401, detail="اسم المستخدم أو كلمة المرور غير صحيحة!")
    
    return {
        "message": "تم تسجيل الدخول بنجاح",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }

def _user_to_dict(u: UserModel):
    # مفيش password هنا عشان ماتتبعتش للمتصفح
    return {"id": u.id, "name": u.name, "email": u.email, "date": u.date, "role": u.role}

class AdminCreateUser(BaseModel):
    name: str
    email: str
    password: str
    role: str = "User"

@app.get("/api/users")
def get_all_users(db: Session = Depends(get_db)):
    return [_user_to_dict(u) for u in db.query(UserModel).order_by(UserModel.id).all()]

@app.post("/api/users")
def admin_add_user(data: AdminCreateUser, db: Session = Depends(get_db)):
    name, email = data.name.strip(), data.email.strip()
    if not name or not email or not data.password:
        raise HTTPException(status_code=400, detail="كل الحقول مطلوبة")
    if db.query(UserModel).filter(UserModel.email == email).first():
        raise HTTPException(status_code=400, detail="البريد الإلكتروني مسجل مسبقاً!")
    role = data.role if data.role in ("User", "Admin") else "User"
    user = UserModel(name=name, email=email, password=data.password,
                     date=datetime.date.today().isoformat(), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return _user_to_dict(user)

@app.delete("/api/users/{user_id}")
def admin_delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="المستخدم غير موجود")
    if user.name == "a":
        raise HTTPException(status_code=400, detail="لا يمكن حذف حساب الأدمن الأساسي")
    db.query(ScanLogModel).filter(ScanLogModel.user_id == user_id).delete()
    db.delete(user)
    db.commit()
    return {"message": "تم حذف المستخدم"}

# ---------------- سجلات الفحص ----------------
def _log_to_dict(l: ScanLogModel):
    return {
        "id": l.id,
        "user_id": l.user_id,
        "element": l.element,
        "scan_type": l.scan_type,
        "is_phishing": bool(l.is_phishing),
        "created_at": l.created_at,
    }

@app.post("/api/logs")
def add_log(data: ScanLogCreate, db: Session = Depends(get_db)):
    log = ScanLogModel(
        user_id=data.user_id,
        element=data.element,
        scan_type=data.scan_type.upper(),
        is_phishing=data.is_phishing,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return _log_to_dict(log)

@app.get("/api/logs/{user_id}")
def get_logs(user_id: int, db: Session = Depends(get_db)):
    logs = (db.query(ScanLogModel)
              .filter(ScanLogModel.user_id == user_id)
              .order_by(ScanLogModel.id.desc())
              .all())
    return [_log_to_dict(l) for l in logs]

@app.delete("/api/logs/user/{user_id}")
def clear_logs(user_id: int, db: Session = Depends(get_db)):
    db.query(ScanLogModel).filter(ScanLogModel.user_id == user_id).delete()
    db.commit()
    return {"message": "تم مسح كل السجلات"}

@app.delete("/api/logs/{log_id}")
def delete_log(log_id: int, db: Session = Depends(get_db)):
    db.query(ScanLogModel).filter(ScanLogModel.id == log_id).delete()
    db.commit()
    return {"message": "تم حذف السجل"}

@app.post("/predict/url")
def predict_url(data: UrlInput):
    if not data.url.strip():
        raise HTTPException(status_code=400, detail="الرابط فارغ")
    result = detector.analyze_url(data.url)
    result["url"] = data.url
    return result

@app.post("/predict/email")
def predict_email(data: EmailInput):
    if not data.text.strip():
        raise HTTPException(status_code=400, detail="النص فارغ")
    return detector.analyze_email(data.text)

@app.post("/predict/qr")
def predict_qr(data: QrInput):
    if not data.text.strip():
        raise HTTPException(status_code=400, detail="محتوى الـ QR فارغ")
    return detector.analyze_qr(data.text)
