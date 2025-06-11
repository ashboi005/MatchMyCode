from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, delete, or_
from sqlalchemy.orm import selectinload, joinedload
from config import get_db
from models import (
    UserProfile, 
    Users, 
    RoleRequest, 
    ModeratorProfile, 
    OrganiserProfile, 
    RecruiterProfile
)
from routers.auth.auth import get_current_user
from .schemas import (
    RoleRequestCreate,
    RoleRequestResponse,
    RoleRequestUpdate,
    RoleRequestListResponse,
    UserDeletionResponse,
    VerificationResponse,
    FileUploadResponse,
    RoleFormRequirementsResponse,
    PermissionCheckResponse,
    ModeratorProfileCreate,
    OrganiserProfileCreate,
    RecruiterProfileCreate
)
from .helpers import moderation_helpers
from typing import Optional, List
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/moderation", tags=["Moderation"])
security = HTTPBearer()

# Helper function to check admin/moderator permissions
async def check_admin_or_moderator(current_user):
    """Check if user is admin or moderator"""
    user_role = current_user["profile"].account_type
    if user_role not in ["ADMIN", "MODERATOR"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Admin or Moderator role required."
        )
    return user_role

async def check_admin_only(current_user):
    """Check if user is admin"""
    user_role = current_user["profile"].account_type
    if user_role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Admin role required."
        )
    return user_role

# 1. User Deletion Route
@router.delete("/user/{user_id}", response_model=UserDeletionResponse)
async def delete_user(
    user_id: str,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a user (Admin and Moderator access)
    
    Access Control:
    - ADMIN can delete any user
    - MODERATOR can delete USER only (not ADMIN, ORGANISER, RECRUITER)
    """
    try:
        # Check permissions
        requester_role = await check_admin_or_moderator(current_user)
        
        # Get target user
        target_user_uuid = uuid.UUID(user_id)
        
        # Get target user profile to check their role
        result = await db.execute(
            select(UserProfile, Users)
            .join(Users, UserProfile.user_id == Users.id)
            .where(Users.id == target_user_uuid)
        )
        user_data = result.first()
        
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        target_profile, target_user = user_data
        target_role = target_profile.account_type or "USER"
        
        # Check if requester can delete this user
        if not moderation_helpers.can_delete_user(requester_role, target_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot delete user with role {target_role}"
            )
        
        # Prevent self-deletion
        if target_user_uuid == current_user["supabase_user"].id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )
        
        # Delete from Supabase Auth (this will cascade to our tables)
        try:
            admin_client = moderation_helpers.admin_client
            admin_client.auth.admin.delete_user(str(target_user_uuid))
        except Exception as e:
            logger.error(f"Failed to delete user from Supabase: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete user from authentication system"
            )
        
        return UserDeletionResponse(
            success=True,
            message=f"User {target_profile.username or target_user.email} deleted successfully",
            deleted_user_id=user_id
        )
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )

# 2. User Verification Route
@router.patch("/verify/{user_id}", response_model=VerificationResponse)
async def toggle_user_verification(
    user_id: str,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Toggle user verification status (Admin and Moderator access)
    
    Used for showing verified badge (like blue tick)
    """
    try:
        # Check permissions
        await check_admin_or_moderator(current_user)
        
        # Get target user
        target_user_uuid = uuid.UUID(user_id)
        
        result = await db.execute(
            select(UserProfile).where(UserProfile.user_id == target_user_uuid)
        )
        target_profile = result.scalar_one_or_none()
        
        if not target_profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Toggle verification status
        target_profile.is_verified = not target_profile.is_verified
        target_profile.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(target_profile)
        
        return VerificationResponse(
            success=True,
            message=f"User {'verified' if target_profile.is_verified else 'unverified'} successfully",
            user_id=user_id,
            is_verified=target_profile.is_verified
        )
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling verification: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update verification status"
        )

# 3. Get Role Form Requirements
@router.get("/role-requirements/{role}", response_model=RoleFormRequirementsResponse)
async def get_role_requirements(
    role: str,
    current_user = Depends(get_current_user)
):
    """
    Get form requirements for specific role application
    
    Available roles: MODERATOR, ORGANISER, RECRUITER
    """
    role = role.upper()
    valid_roles = ["MODERATOR", "ORGANISER", "RECRUITER"]
    
    if role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Valid roles: {', '.join(valid_roles)}"
        )
    
    requirements = moderation_helpers.get_role_form_requirements(role)
    
    if not requirements:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role requirements not found"
        )
    
    return RoleFormRequirementsResponse(
        role=role,
        requirements=requirements,
        description=requirements.get("description", f"Requirements for {role} role")
    )

# 4. Upload Role Document
@router.post("/upload-role-document", response_model=FileUploadResponse)
async def upload_role_document(
    document_type: str = Form(..., description="Type of document: license, event_history"),
    file: UploadFile = File(..., description="PDF document"),
    current_user = Depends(get_current_user)
):
    """
    Upload document for role application
    
    Document types: license, event_history
    """
    valid_document_types = ["license", "event_history"]
    
    if document_type not in valid_document_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid document type. Valid types: {', '.join(valid_document_types)}"
        )
    
    try:
        user_id = str(current_user["supabase_user"].id)
        file_url = await moderation_helpers.upload_role_document(user_id, file, document_type)
        
        return FileUploadResponse(
            file_url=file_url,
            message=f"{document_type.title()} document uploaded successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading role document: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload document"
        )

# 5. Role Request Route
@router.post("/request-role", response_model=RoleRequestResponse)
async def request_role(
    role_request: RoleRequestCreate,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Request role upgrade
    
    Available roles: MODERATOR, ORGANISER, RECRUITER
    Users can request role upgrade with required documents
    """
    try:
        user_id = current_user["supabase_user"].id
        user_profile = current_user["profile"]
        
        # Validate role
        valid_roles = ["MODERATOR", "ORGANISER", "RECRUITER"]
        desired_role = role_request.desired_role.upper()
        
        if desired_role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Valid roles: {', '.join(valid_roles)}"
            )
        
        # Check if user already has a pending request for this role
        existing_request = await db.execute(
            select(RoleRequest).where(
                and_(
                    RoleRequest.user_id == user_id,
                    RoleRequest.requested_role == desired_role,
                    RoleRequest.status == "PENDING"
                )
            )
        )
        
        if existing_request.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"You already have a pending request for {desired_role} role"
            )
          # Create role-specific profile based on role type
        profile_id = None
        
        if desired_role == "MODERATOR":
            profile_data = ModeratorProfileCreate(**role_request.details)
            moderator_profile = ModeratorProfile(
                user_id=user_id,
                experience_summary=profile_data.experience_summary,
                moderation_experience_years=profile_data.moderation_experience_years
            )
            db.add(moderator_profile)
            await db.flush()
            profile_id = moderator_profile.id
            
        elif desired_role == "ORGANISER":
            profile_data = OrganiserProfileCreate(**role_request.details)
            organiser_profile = OrganiserProfile(
                user_id=user_id,
                event_history_pdf=profile_data.event_history_pdf,
                organization_name=profile_data.organization_name,
                years_active=profile_data.years_active
            )
            db.add(organiser_profile)
            await db.flush()
            profile_id = organiser_profile.id
            
        elif desired_role == "RECRUITER":
            profile_data = RecruiterProfileCreate(**role_request.details)
            
            # Check if LinkedIn URL is provided, otherwise get from user profile
            linkedin_url = profile_data.linkedin_url
            if not linkedin_url:
                linkedin_url = await moderation_helpers.get_user_linkedin_url(db, user_id)
                if not linkedin_url:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="LinkedIn URL is required. Please add it to your profile or provide it in the request."
                    )
            
            recruiter_profile = RecruiterProfile(
                user_id=user_id,
                recruiter_license_pdf=profile_data.recruiter_license_pdf,
                company_name=profile_data.company_name,
                linkedin_url=linkedin_url
            )
            db.add(recruiter_profile)
            await db.flush()
            profile_id = recruiter_profile.id
        
        # Create role request
        role_request_obj = RoleRequest(
            user_id=user_id,
            requested_role=desired_role,
            status="PENDING"
        )
        
        db.add(role_request_obj)
        await db.commit()
        await db.refresh(role_request_obj)
        
        return RoleRequestResponse(
            id=str(role_request_obj.id),
            user_id=str(role_request_obj.user_id),
            requested_role=role_request_obj.requested_role,
            status=role_request_obj.status,
            created_at=role_request_obj.created_at,
            updated_at=role_request_obj.updated_at,
            username=user_profile.username,
            first_name=user_profile.first_name,
            last_name=user_profile.last_name,
            display_name=user_profile.display_name,
            profile_data=role_request.details
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating role request: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create role request"
        )

# 6. Get Role Requests (Admin only)
@router.get("/role-requests", response_model=RoleRequestListResponse)
async def get_role_requests(
    status_filter: Optional[str] = Query(None, description="Filter by status: PENDING, APPROVED, REJECTED"),
    role_filter: Optional[str] = Query(None, description="Filter by role: MODERATOR, ORGANISER, RECRUITER"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get role requests with user and profile data (Admin only)
    """
    # Check admin permissions
    await check_admin_only(current_user)
    
    try:
        # Build query
        query = select(RoleRequest, UserProfile, Users.email).join(
            UserProfile, RoleRequest.user_id == UserProfile.user_id
        ).join(
            Users, RoleRequest.user_id == Users.id
        )
        
        # Apply filters
        if status_filter:
            query = query.where(RoleRequest.status == status_filter.upper())
        
        if role_filter:
            query = query.where(RoleRequest.requested_role == role_filter.upper())
        
        # Get total count
        count_query = select(func.count(RoleRequest.id))
        if status_filter:
            count_query = count_query.where(RoleRequest.status == status_filter.upper())
        if role_filter:
            count_query = count_query.where(RoleRequest.requested_role == role_filter.upper())
        
        total_result = await db.execute(count_query)
        total_count = total_result.scalar()
        
        # Apply pagination and ordering
        query = query.order_by(RoleRequest.created_at.desc())
        query = query.offset((page - 1) * limit).limit(limit)
        
        result = await db.execute(query)
        requests_data = result.all()
          # Build response with profile data
        requests = []
        for role_request, user_profile, email in requests_data:
            # Get role-specific profile data
            profile_data = None
            
            if role_request.requested_role == "MODERATOR":
                moderator_result = await db.execute(
                    select(ModeratorProfile).where(ModeratorProfile.user_id == role_request.user_id)
                )
                moderator_profile = moderator_result.scalar_one_or_none()
                if moderator_profile:
                    profile_data = {
                        "experience_summary": moderator_profile.experience_summary,
                        "moderation_experience_years": moderator_profile.moderation_experience_years
                    }
            
            elif role_request.requested_role == "ORGANISER":
                organiser_result = await db.execute(
                    select(OrganiserProfile).where(OrganiserProfile.user_id == role_request.user_id)
                )
                organiser_profile = organiser_result.scalar_one_or_none()
                if organiser_profile:
                    profile_data = {
                        "event_history_pdf": organiser_profile.event_history_pdf,
                        "organization_name": organiser_profile.organization_name,
                        "years_active": organiser_profile.years_active
                    }
            
            elif role_request.requested_role == "RECRUITER":
                recruiter_result = await db.execute(
                    select(RecruiterProfile).where(RecruiterProfile.user_id == role_request.user_id)
                )
                recruiter_profile = recruiter_result.scalar_one_or_none()
                if recruiter_profile:
                    profile_data = {
                        "recruiter_license_pdf": recruiter_profile.recruiter_license_pdf,
                        "company_name": recruiter_profile.company_name,
                        "linkedin_url": recruiter_profile.linkedin_url
                    }
            
            requests.append(RoleRequestResponse(
                id=str(role_request.id),
                user_id=str(role_request.user_id),
                requested_role=role_request.requested_role,
                status=role_request.status,
                created_at=role_request.created_at,
                updated_at=role_request.updated_at,
                username=user_profile.username,
                first_name=user_profile.first_name,
                last_name=user_profile.last_name,
                display_name=user_profile.display_name,
                email=email,
                profile_data=profile_data
            ))
        
        return RoleRequestListResponse(
            requests=requests,
            total_count=total_count,
            page=page,
            limit=limit
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting role requests: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get role requests"
        )

# 7. Update Role Request Status (Admin only)
@router.patch("/role-requests/{request_id}", response_model=RoleRequestResponse)
async def update_role_request_status(
    request_id: str,
    update_data: RoleRequestUpdate,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Approve or reject role request (Admin only)
    
    If APPROVED: Updates user's account_type
    If REJECTED: No change to user's role
    """
    # Check admin permissions
    await check_admin_only(current_user)
    
    try:
        # Validate status
        valid_statuses = ["APPROVED", "REJECTED"]
        if update_data.status.upper() not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Valid statuses: {', '.join(valid_statuses)}"
            )
        
        # Get role request
        request_uuid = uuid.UUID(request_id)
        
        result = await db.execute(
            select(RoleRequest, UserProfile).join(
                UserProfile, RoleRequest.user_id == UserProfile.user_id
            ).where(RoleRequest.id == request_uuid)
        )
        
        request_data = result.first()
        if not request_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role request not found"
            )
        
        role_request, user_profile = request_data
        
        # Check if request is still pending
        if role_request.status != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Request already {role_request.status.lower()}"
            )
        
        # Update request status
        role_request.status = update_data.status.upper()
        role_request.updated_at = datetime.utcnow()
        
        # If approved, update user's account_type
        if update_data.status.upper() == "APPROVED":
            user_profile.account_type = role_request.requested_role
            user_profile.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(role_request)
        await db.refresh(user_profile)
        
        return RoleRequestResponse(
            id=str(role_request.id),
            user_id=str(role_request.user_id),
            requested_role=role_request.requested_role,
            status=role_request.status,
            created_at=role_request.created_at,
            updated_at=role_request.updated_at,
            username=user_profile.username,
            first_name=user_profile.first_name,
            last_name=user_profile.last_name,
            display_name=user_profile.display_name
        )
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request ID format"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating role request: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update role request"
        )

# 8. Check Permissions (Utility endpoint)
@router.get("/check-permissions", response_model=PermissionCheckResponse)
async def check_permissions(
    action: str = Query(..., description="Action to check: delete, verify, approve_role_request"),
    target_role: Optional[str] = Query(None, description="Target user role (for delete action)"),
    current_user = Depends(get_current_user)
):
    """
    Check if current user has permission for specific action
    """
    user_role = current_user["profile"].account_type or "USER"
    
    has_permission = moderation_helpers.check_role_permissions(
        user_role=user_role,
        action=action,
        target_role=target_role
    )
    
    return PermissionCheckResponse(
        has_permission=has_permission,
        user_role=user_role,
        action=action,
        target_role=target_role
    )