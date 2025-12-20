from fastapi import FastAPI, Depends, HTTPException, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
import database, models, schemas
import os
import pytz
from contextlib import asynccontextmanager
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    import bcrypt

    BCRYPT_AVAILABLE = True
    print("bcrypt available")
except ImportError:
    print("bcrypt not available, using fallback")
    BCRYPT_AVAILABLE = False



def get_password_hash(password: str) -> str:
    if BCRYPT_AVAILABLE:
        password_bytes = password.encode('utf-8')
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
            print("Password truncated to 72 bytes for bcrypt")
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    else:
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if BCRYPT_AVAILABLE:
        try:
            password_bytes = plain_password.encode('utf-8')
            hashed_bytes = hashed_password.encode('utf-8')
            if len(password_bytes) > 72:
                password_bytes = password_bytes[:72]
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except Exception as e:
            print(f"Error verifying password with bcrypt: {e}")
            return False
    else:
        import hashlib
        return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password



@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 50)
    print("Starting Tax Calculation Service")
    print(f"Bcrypt available: {BCRYPT_AVAILABLE}")

    # 1. Асинхронное создание таблиц
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    print("✓ Tables created successfully")

    # 2. Асинхронная проверка и создание начального пользователя
    async with database.AsyncSessionLocal() as session:
        try:
            # Используем execute для асинхронного запроса
            result = await session.execute(select(models.User))
            users = result.scalars().all()
            user_count = len(users)

            print(f"✓ Users in database: {user_count}")
            if user_count == 0:
                print("Creating initial user...")
                password = "Admin123"
                hashed_password = get_password_hash(password)
                user = models.User(
                    email="admin@taxservice.com",
                    hashed_password=hashed_password,
                    full_name="Administrator",
                    company_name="Test Company",
                    inn="1234567890"
                )
                session.add(user)
                await session.commit()
                print(f"✓ Created user: admin@taxservice.com / {password}")
                print("Note: Use these credentials to login")
        except Exception as e:
            print(f"Error during startup: {e}")
            import traceback
            traceback.print_exc()

    print("=" * 50)
    yield

    print("=" * 50)
    print("Shutting down Tax Service")
    print("=" * 50)


app = FastAPI(
    title="Tax Calculation Automation Service",
    description="Сервис автоматизации налоговых расчетов - Налоговые формы, сроки, уведомления",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

if not os.path.exists("templates"):
    os.makedirs("templates")
templates = Jinja2Templates(directory="templates")

moscow_tz = pytz.timezone('Europe/Moscow')
SECRET_KEY = os.getenv("SECRET_KEY", "tax-service-dev-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security_scheme = HTTPBearer()



async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(
        select(models.User).filter(models.User.email == email)
    )
    return result.scalar_one_or_none()


async def authenticate_user(db: AsyncSession, email: str, password: str):
    user = await get_user_by_email(db, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user_for_api(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
        db: AsyncSession = Depends(database.get_db)
):
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_current_user_for_web(request: Request, db: AsyncSession = Depends(database.get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except JWTError:
        return None

    return await get_user_by_email(db, email)


def require_auth_for_api(current_user: models.User = Depends(get_current_user_for_api)):
    return current_user


def require_auth_for_web(current_user=Depends(get_current_user_for_web)):
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login-page"}
        )
    return current_user


# REST API эндпоинты (все асинхронные)
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": None,
        "tax_forms_count": 0,
        "deadlines_count": 0,
        "notifications_count": 0
    })


@app.get("/login-page", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register-page", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


# CRUD для TaxForm
@app.post("/tax-forms/", response_model=schemas.TaxForm)
async def create_tax_form(
        tax_form: schemas.TaxFormCreate,
        current_user: models.User = Depends(require_auth_for_api),
        db: AsyncSession = Depends(database.get_db)
):
    db_tax_form = models.TaxForm(
        **tax_form.dict(),
        user_id=current_user.id
    )
    db.add(db_tax_form)
    await db.commit()
    await db.refresh(db_tax_form)
    return db_tax_form


@app.get("/tax-forms/", response_model=List[schemas.TaxForm])
async def read_tax_forms(
        skip: int = 0,
        limit: int = 100,
        current_user: models.User = Depends(require_auth_for_api),
        db: AsyncSession = Depends(database.get_db)
):
    result = await db.execute(
        select(models.TaxForm)
        .filter(models.TaxForm.user_id == current_user.id)
        .offset(skip)
        .limit(limit)
    )
    tax_forms = result.scalars().all()
    return tax_forms


@app.get("/tax-forms/{tax_form_id}", response_model=schemas.TaxForm)
async def read_tax_form(
        tax_form_id: int,
        current_user: models.User = Depends(require_auth_for_api),
        db: AsyncSession = Depends(database.get_db)
):
    result = await db.execute(
        select(models.TaxForm)
        .filter(models.TaxForm.id == tax_form_id)
        .filter(models.TaxForm.user_id == current_user.id)
    )
    tax_form = result.scalar_one_or_none()
    if tax_form is None:
        raise HTTPException(status_code=404, detail="Tax form not found")
    return tax_form


@app.put("/tax-forms/{tax_form_id}", response_model=schemas.TaxForm)
async def update_tax_form(
        tax_form_id: int,
        tax_form_update: schemas.TaxFormCreate,
        current_user: models.User = Depends(require_auth_for_api),
        db: AsyncSession = Depends(database.get_db)
):
    result = await db.execute(
        select(models.TaxForm)
        .filter(models.TaxForm.id == tax_form_id)
        .filter(models.TaxForm.user_id == current_user.id)
    )
    db_tax_form = result.scalar_one_or_none()
    if db_tax_form is None:
        raise HTTPException(status_code=404, detail="Tax form not found")

    for key, value in tax_form_update.dict().items():
        setattr(db_tax_form, key, value)

    await db.commit()
    await db.refresh(db_tax_form)
    return db_tax_form


@app.delete("/tax-forms/{tax_form_id}")
async def delete_tax_form(
        tax_form_id: int,
        current_user: models.User = Depends(require_auth_for_api),
        db: AsyncSession = Depends(database.get_db)
):
    result = await db.execute(
        select(models.TaxForm)
        .filter(models.TaxForm.id == tax_form_id)
        .filter(models.TaxForm.user_id == current_user.id)
    )
    db_tax_form = result.scalar_one_or_none()
    if db_tax_form is None:
        raise HTTPException(status_code=404, detail="Tax form not found")

    await db.delete(db_tax_form)
    await db.commit()
    return {"message": "Tax form deleted successfully"}


# CRUD для Deadline
@app.post("/deadlines/", response_model=schemas.Deadline)
async def create_deadline(
        deadline: schemas.DeadlineCreate,
        current_user: models.User = Depends(require_auth_for_api),
        db: AsyncSession = Depends(database.get_db)
):
    # Проверяем, что форма принадлежит пользователю
    result = await db.execute(
        select(models.TaxForm)
        .filter(models.TaxForm.id == deadline.tax_form_id)
        .filter(models.TaxForm.user_id == current_user.id)
    )
    tax_form = result.scalar_one_or_none()
    if tax_form is None:
        raise HTTPException(status_code=404, detail="Tax form not found")

    db_deadline = models.Deadline(
        **deadline.dict(),
        user_id=current_user.id
    )
    db.add(db_deadline)
    await db.commit()
    await db.refresh(db_deadline)
    return db_deadline


@app.get("/deadlines/", response_model=List[schemas.Deadline])
async def read_deadlines(
        skip: int = 0,
        limit: int = 100,
        status: Optional[str] = None,
        current_user: models.User = Depends(require_auth_for_api),
        db: AsyncSession = Depends(database.get_db)
):
    query = select(models.Deadline).filter(
        models.Deadline.user_id == current_user.id
    )
    if status:
        query = query.filter(models.Deadline.status == status)
    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    deadlines = result.scalars().all()
    return deadlines


@app.patch("/deadlines/{deadline_id}", response_model=schemas.Deadline)
async def update_deadline(
        deadline_id: int,
        deadline_update: schemas.DeadlineUpdate,
        current_user: models.User = Depends(require_auth_for_api),
        db: AsyncSession = Depends(database.get_db)
):
    result = await db.execute(
        select(models.Deadline)
        .filter(models.Deadline.id == deadline_id)
        .filter(models.Deadline.user_id == current_user.id)
    )
    db_deadline = result.scalar_one_or_none()
    if db_deadline is None:
        raise HTTPException(status_code=404, detail="Deadline not found")

    update_data = deadline_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_deadline, key, value)

    await db.commit()
    await db.refresh(db_deadline)
    return db_deadline


# Аутентификация
@app.post("/register", response_model=schemas.User)
async def register_user(
        user: schemas.UserCreate,
        db: AsyncSession = Depends(database.get_db)
):
    # Проверяем существующий email
    result = await db.execute(
        select(models.User).filter(models.User.email == user.email)
    )
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # Проверяем существующий INN
    result = await db.execute(
        select(models.User).filter(models.User.inn == user.inn)
    )
    existing_inn = result.scalar_one_or_none()
    if existing_inn:
        raise HTTPException(
            status_code=400,
            detail="INN already registered"
        )

    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
        company_name=user.company_name,
        inn=user.inn
    )

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


@app.post("/login")
async def login(
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(database.get_db)
):
    user = await authenticate_user(db, email, password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name
    }


# Хелсчек
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Tax Calculation Automation",
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    import uvicorn

    print("\n" + "=" * 60)
    print("TAX CALCULATION AUTOMATION SERVICE")
    print("=" * 60)
    print("Server is running!")
    print("Use these URLs to access the service:")
    print(f"   Web interface:  http://localhost:8000")
    print(f"   API Docs:       http://localhost:8000/docs")
    print(f"   ReDoc:          http://localhost:8000/redoc")
    print(f"   Test user:      admin@taxservice.com / Admin123")
    print("=" * 60)
    print("Press CTRL+C to stop the server")
    print("=" * 60 + "\n")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )