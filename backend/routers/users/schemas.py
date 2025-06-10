from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserProfileUpdate(BaseModel):
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    github_username: Optional[str] = None
    twitter_handle: Optional[str] = None
    resume_url: Optional[str] = None

class ProfileImageUpload(BaseModel):
    """Response schema for profile image upload"""
    avatar_url: str
    message: str

class UserProfileResponse(BaseModel):
    id: str
    user_id: str
    email: str
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    github_username: Optional[str] = None
    twitter_handle: Optional[str] = None
    resume_url: Optional[str] = None
    preferences: Optional[dict] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class UserProfilePublic(BaseModel):
    """Public profile information (without email)"""
    id: str
    user_id: str
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    github_username: Optional[str] = None
    twitter_handle: Optional[str] = None
    resume_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
