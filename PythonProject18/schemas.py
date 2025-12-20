from pydantic import BaseModel, validator, field_validator, EmailStr
from typing import Optional, List
from datetime import datetime, date
from enum import Enum


# Перечисления
class NotificationType(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"


class DeadlineStatus(str, Enum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    OVERDUE = "overdue"
    EXTENDED = "extended"


# Базовые схемы
class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    company_name: str
    inn: str


class UserCreate(UserBase):
    password: str

    @field_validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        if len(v) > 72:
            raise ValueError('Password must be less than 72 characters')
        return v

    @field_validator('inn')
    def validate_inn(cls, v):
        if not v.isdigit() or len(v) != 10:
            raise ValueError('INN must be 10 digits')
        return v


class User(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Схемы для налоговых форм
class TaxFormBase(BaseModel):
    form_code: str
    form_name: str
    description: Optional[str] = None
    tax_period: str

    @field_validator('form_code')
    def validate_form_code(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Form code cannot be empty')
        return v.strip().upper()

    @field_validator('tax_period')
    def validate_tax_period(cls, v):
        valid_periods = ['month', 'quarter', 'year']
        if v not in valid_periods:
            raise ValueError(f'Tax period must be one of: {", ".join(valid_periods)}')
        return v


class TaxFormCreate(TaxFormBase):
    pass


class TaxForm(TaxFormBase):
    id: int
    is_active: bool
    created_at: datetime
    user_id: int

    class Config:
        from_attributes = True


# Схемы для сроков сдачи
class DeadlineBase(BaseModel):
    tax_form_id: int
    deadline_date: date
    status: Optional[DeadlineStatus] = DeadlineStatus.PENDING
    penalty_amount: Optional[float] = 0.0
    comment: Optional[str] = None

    @field_validator('penalty_amount')
    def validate_penalty_amount(cls, v):
        if v < 0:
            raise ValueError('Penalty amount cannot be negative')
        return v


class DeadlineCreate(DeadlineBase):
    pass


class DeadlineUpdate(BaseModel):
    submission_date: Optional[date] = None
    status: Optional[DeadlineStatus] = None
    penalty_amount: Optional[float] = None
    comment: Optional[str] = None


class Deadline(DeadlineBase):
    id: int
    submission_date: Optional[date] = None
    created_at: datetime
    user_id: int

    class Config:
        from_attributes = True


# Схемы для уведомлений
class NotificationBase(BaseModel):
    title: str
    message: str
    notification_type: Optional[NotificationType] = NotificationType.INFO

    @field_validator('title')
    def validate_title(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Title cannot be empty')
        if len(v) > 200:
            raise ValueError('Title must be less than 200 characters')
        return v.strip()


class NotificationCreate(NotificationBase):
    pass


class NotificationUpdate(BaseModel):
    is_read: Optional[bool] = None
    notification_type: Optional[NotificationType] = None


class Notification(NotificationBase):
    id: int
    is_read: bool
    read_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    user_id: int

    class Config:
        from_attributes = True


# Схемы для аутентификации
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str