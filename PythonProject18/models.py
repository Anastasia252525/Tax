from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean, Date
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.ext.asyncio import AsyncSession
from database import Base
from datetime import datetime
import pytz

moscow_tz = pytz.timezone('Europe/Moscow')


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    company_name = Column(String, nullable=False)
    inn = Column(String, unique=True, nullable=False)  # ИНН организации
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(moscow_tz))

    # Связи
    tax_forms = relationship("TaxForm", back_populates="user", cascade="all, delete-orphan")
    deadlines = relationship("Deadline", back_populates="user", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="user", cascade="all, delete-orphan")


class TaxForm(Base):
    __tablename__ = "tax_forms"
    id = Column(Integer, primary_key=True, index=True)
    form_code = Column(String, index=True, nullable=False)  # Код формы (НДС-1, 3-НДФЛ и т.д.)
    form_name = Column(String, nullable=False)  # Название формы
    description = Column(Text)  # Описание формы
    tax_period = Column(String, nullable=False)  # Налоговый период (месяц, квартал, год)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(moscow_tz))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))

    # Связи
    user = relationship("User", back_populates="tax_forms")
    deadlines = relationship("Deadline", back_populates="tax_form", cascade="all, delete-orphan")


class Deadline(Base):
    __tablename__ = "deadlines"
    id = Column(Integer, primary_key=True, index=True)
    tax_form_id = Column(Integer, ForeignKey("tax_forms.id", ondelete="CASCADE"))
    deadline_date = Column(Date, nullable=False)  # Дата сдачи
    submission_date = Column(Date, nullable=True)  # Фактическая дата сдачи
    status = Column(String, default="pending")  # pending, submitted, overdue, extended
    penalty_amount = Column(Float, default=0.0)  # Сумма штрафа
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(moscow_tz))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))

    # Связи
    tax_form = relationship("TaxForm", back_populates="deadlines")
    user = relationship("User", back_populates="deadlines")


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)  # Заголовок уведомления
    message = Column(Text, nullable=False)  # Текст уведомления
    notification_type = Column(String, default="info")  # info, warning, error, success
    is_read = Column(Boolean, default=False)
    read_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(moscow_tz))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(moscow_tz))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))

    # Связи
    user = relationship("User", back_populates="notifications")