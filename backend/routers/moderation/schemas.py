from pydantic import BaseModel, EmailStr, HttpUrl, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid

# Role Request Schemas
class RoleRequestCreate(BaseModel):
    """Request to upgrade user role"""
    desired_role: str = Field(..., description="Role to request: MODERATOR, ORGANISER, or RECRUITER")
    details: Dict[str, Any] = Field(..., description="Role-specific details and documents")

class ModeratorProfileCreate(BaseModel):
    """Moderator profile creation"""
    experience_summary: str = Field(..., description="Summary of relevant experience")
    moderation_experience_years: int = Field(..., ge=0, description="Years of moderation experience")

class OrganiserProfileCreate(BaseModel):
    """Organiser profile creation"""
    event_history_pdf: str = Field(..., description="URL to event history PDF")
    organization_name: str = Field(..., description="Name of organization")
    years_active: int = Field(..., ge=0, description="Years actively organizing events")

class RecruiterProfileCreate(BaseModel):
    """Recruiter profile creation"""
    recruiter_license_pdf: str = Field(..., description="URL to recruiter license PDF")
    company_name: str = Field(..., description="Company name")
    linkedin_url: Optional[str] = Field(None, description="LinkedIn URL if not in user profile")

# Response Schemas
class RoleRequestResponse(BaseModel):
    """Role request response"""
    id: str
    user_id: str
    requested_role: str
    status: str
    created_at: datetime
    updated_at: datetime
    
    # User details
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    email: Optional[str] = None
    
    # Role-specific profile data
    profile_data: Optional[Dict[str, Any]] = None
    
    # Additional fields for status updates
    message: Optional[str] = None
    metadata_updated: Optional[bool] = None
    note: Optional[str] = None

    class Config:
        from_attributes = True

class RoleRequestUpdate(BaseModel):
    """Update role request status"""
    status: str = Field(..., description="New status: APPROVED or REJECTED")

class UserDeletionResponse(BaseModel):
    """Response for user deletion"""
    success: bool
    message: str
    deleted_user_id: str

class VerificationResponse(BaseModel):
    """Response for user verification toggle"""
    success: bool
    message: str
    user_id: str
    is_verified: bool

class RoleRequestListResponse(BaseModel):
    """Response for role requests list"""
    requests: List[RoleRequestResponse]
    total_count: int
    page: int
    limit: int

# Upload response schemas
class FileUploadResponse(BaseModel):
    """Response for file upload"""
    file_url: str
    message: str

# Form requirement schemas for different roles
class ModeratorFormRequirements(BaseModel):
    """Required fields for moderator application"""
    experience_summary_required: bool = True
    moderation_years_required: bool = True
    
class OrganiserFormRequirements(BaseModel):
    """Required fields for organiser application"""
    event_history_pdf_required: bool = True
    organization_name_required: bool = True
    years_active_required: bool = True

class RecruiterFormRequirements(BaseModel):
    """Required fields for recruiter application"""
    recruiter_license_pdf_required: bool = True
    company_name_required: bool = True
    linkedin_url_required: bool = False  # Optional if already in user profile

class RoleFormRequirementsResponse(BaseModel):
    """Response containing form requirements for a specific role"""
    role: str
    requirements: Dict[str, Any]
    description: str

# Permission check schemas
class PermissionCheckResponse(BaseModel):
    """Response for permission checks"""
    has_permission: bool
    user_role: str
    action: str
    target_role: Optional[str] = None
