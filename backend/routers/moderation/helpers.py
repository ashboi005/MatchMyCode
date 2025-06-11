from fastapi import HTTPException, status, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import UserProfile, Users
from config import get_supabase_admin_client, get_supabase_storage
import uuid
import os
from typing import List, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

class ModerationHelpers:
    """Helper functions for moderation operations"""
    
    def __init__(self):
        self._admin_client = None
        self._storage = None
    
    @property
    def admin_client(self):
        if self._admin_client is None:
            self._admin_client = get_supabase_admin_client()
        return self._admin_client
    
    @property
    def storage(self):
        if self._storage is None:
            self._storage = get_supabase_storage()
        return self._storage

    def check_role_permissions(self, user_role: str, action: str, target_role: Optional[str] = None) -> bool:
        """
        Check if user has permission to perform action
        
        Args:
            user_role: Role of the user performing action
            action: Action being performed (delete, verify, approve_role_request)
            target_role: Role of target user (for deletion)
        
        Returns:
            bool: True if permission granted
        """
        if user_role == "ADMIN":
            return True
        
        if user_role == "MODERATOR":
            if action == "delete":
                # Moderators can delete USER only
                return target_role == "USER"
            elif action == "verify":
                return True
            elif action == "approve_role_request":
                return False  # Only admins can approve role requests
        
        return False
    
    def can_delete_user(self, requester_role: str, target_role: str) -> bool:
        """Check if requester can delete target user"""
        if requester_role == "ADMIN":
            return True
        
        if requester_role == "MODERATOR":
            # Moderators cannot delete ADMIN, ORGANISER, or RECRUITER
            forbidden_roles = ["ADMIN", "ORGANISER", "RECRUITER", "MODERATOR"]
            return target_role not in forbidden_roles
        
        return False
    
    async def upload_role_document(self, user_id: str, file: UploadFile, document_type: str) -> str:
        """
        Upload role-related document to Supabase Storage
        
        Args:
            user_id: User ID
            file: Uploaded file
            document_type: Type of document (cv, license, event_history)
        
        Returns:
            str: Public URL of uploaded file
        """
        try:
            # Validate file type
            allowed_types = ["application/pdf"]
            if file.content_type not in allowed_types:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File type {file.content_type} not allowed. Only PDF files are accepted."
                )
            
            # Validate file size (max 10MB for documents)
            file_content = await file.read()
            if len(file_content) > 10 * 1024 * 1024:  # 10MB
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="File size must be less than 10MB"
                )
            
            await file.seek(0)
            
            # Generate unique filename
            file_extension = os.path.splitext(file.filename)[1] if file.filename else '.pdf'
            unique_filename = f"role_documents/{user_id}/{document_type}/{uuid.uuid4()}{file_extension}"
            
            bucket_name = os.getenv("SUPABASE_STORAGE_BUCKET", "blog-media")
            
            # Upload to Supabase Storage
            response = self.admin_client.storage.from_(bucket_name).upload(
                path=unique_filename,
                file=file_content,
                file_options={"content-type": file.content_type}
            )
            
            if hasattr(response, 'error') and response.error:
                logger.error(f"Upload error: {response.error}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to upload document"
                )
            
            # Get public URL
            public_url = self.admin_client.storage.from_(bucket_name).get_public_url(unique_filename)
            logger.info(f"Document uploaded successfully: {public_url}")
            
            return public_url
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error uploading document: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to upload document"
            )
    
    async def delete_role_document(self, document_url: str) -> bool:
        """
        Delete role document from Supabase Storage
        
        Args:
            document_url: URL of document to delete
        
        Returns:
            bool: True if successfully deleted
        """
        try:
            bucket_name = os.getenv("SUPABASE_STORAGE_BUCKET", "blog-media")
            
            if "/storage/v1/object/public/" in document_url:
                parts = document_url.split("/storage/v1/object/public/")[1]
                path_parts = parts.split("/", 1)
                if len(path_parts) > 1:
                    file_path = path_parts[1]
                    
                    response = self.storage.from_(bucket_name).remove([file_path])
                    
                    if response.get("error"):
                        logger.warning(f"Failed to delete document: {response['error']}")
                        return False
                    
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error deleting document: {str(e)}")
            return False
    
    def get_role_form_requirements(self, role: str) -> Dict[str, Any]:
        """
        Get form requirements for specific role
        
        Args:
            role: Role type (MODERATOR, ORGANISER, RECRUITER)
          Returns:
            Dict containing requirements and descriptions
        """
        requirements = {
            "MODERATOR": {
                "experience_summary_required": True,
                "moderation_years_required": True,
                "description": "Apply to become a moderator. You'll need to provide your experience summary and years of moderation experience. Your resume will be taken from your user profile (please ensure it's uploaded).",
                "fields": {
                    "experience_summary": {"type": "textarea", "required": True, "label": "Experience Summary"},
                    "moderation_experience_years": {"type": "number", "min": 0, "required": True, "label": "Years of Moderation Experience"}
                }
            },
            "ORGANISER": {
                "event_history_pdf_required": True,
                "organization_name_required": True,
                "years_active_required": True,
                "description": "Apply to become an event organiser. You'll need to provide event history documentation, organization details, and experience.",
                "fields": {
                    "event_history_pdf": {"type": "file", "accept": ".pdf", "required": True, "label": "Event History (PDF)"},
                    "organization_name": {"type": "text", "required": True, "label": "Organization Name"},
                    "years_active": {"type": "number", "min": 0, "required": True, "label": "Years Active in Event Organization"}
                }
            },
            "RECRUITER": {
                "recruiter_license_pdf_required": True,
                "company_name_required": True,
                "linkedin_url_required": False,
                "description": "Apply to become a recruiter. You'll need to provide recruiter license, company details, and professional information.",
                "fields": {
                    "recruiter_license_pdf": {"type": "file", "accept": ".pdf", "required": True, "label": "Recruiter License (PDF)"},
                    "company_name": {"type": "text", "required": True, "label": "Company Name"},
                    "linkedin_url": {"type": "url", "required": False, "label": "LinkedIn URL (if not in profile)"}
                }
            }
        }
        
        return requirements.get(role, {})
    
    async def get_user_linkedin_url(self, db: AsyncSession, user_id: uuid.UUID) -> Optional[str]:
        """
        Get user's LinkedIn URL from their profile
        
        Args:
            db: Database session
            user_id: User ID
        
        Returns:
            Optional[str]: LinkedIn URL if found
        """
        try:
            result = await db.execute(
                select(UserProfile.linkedin_url).where(UserProfile.user_id == user_id)
            )
            linkedin_url = result.scalar_one_or_none()
            return linkedin_url
        except Exception as e:
            logger.error(f"Error getting LinkedIn URL: {str(e)}")
            return None

moderation_helpers = ModerationHelpers()
