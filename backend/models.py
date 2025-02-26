from sqlalchemy import Column, Integer, String, Enum, ForeignKey
from sqlalchemy.orm import relationship
import enum
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class UserRole(enum.Enum):
    USER = "USER"
    MENTOR = "MENTOR"
    ORGANIZER = "ORGANIZER"
    ADMIN = "ADMIN"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    clerkId = Column(String, unique=True, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    phone_number = Column(String, unique=True, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    details = relationship("UserDetails", back_populates="user", uselist=False, cascade="all, delete-orphan")

