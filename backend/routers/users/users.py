from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, exists
from config import get_db
from models import UserProfile, UserFollower, Users
from routers.auth.auth import get_current_user
from dependencies.rbac import (
    require_users_me, 
    require_users_me_write,
    require_users_profiles,
    require_users_follow,
    require_users_follow_write,
    require_admin_users,
    require_admin_or_moderator
)
from .schemas import (
    UserProfileUpdate,
    UserProfileResponse,
    ProfileImageUpload,
    UserProfilePublic,
    FollowUserRequest,
    FollowerUser,
    FollowersResponse,
    FollowingResponse,
    FollowStatsResponse,
    FollowActionResponse
)
from .helpers import user_helpers
from typing import Optional
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])

security = HTTPBearer()

@router.get("/me", response_model=UserProfileResponse)
async def get_current_user_profile(
    current_user = Depends(get_current_user),
    _rbac_check = Depends(require_users_me)
):
    """
    Get current user's profile information
    
    **Requires user profile read permission**
    """
    profile = current_user["profile"]
    supabase_user = current_user["supabase_user"]
    
    return UserProfileResponse(
        id=str(profile.id),
        user_id=str(profile.user_id),
        username=profile.username,
        email=supabase_user.email,  
        first_name=profile.first_name,
        last_name=profile.last_name,
        display_name=profile.display_name,
        bio=profile.bio,
        avatar_url=profile.avatar_url,
        date_of_birth=profile.date_of_birth,
        timezone=profile.timezone,
        language=profile.language,
        account_type=profile.account_type,
        is_verified=profile.is_verified,
        github_username=profile.github_username,
        twitter_handle=profile.twitter_handle,
        resume_url=profile.resume_url,
        preferences=profile.preferences,
        created_at=profile.created_at,
        updated_at=profile.updated_at
    )

@router.put("/me", response_model=UserProfileResponse)
async def update_current_user_profile(
    profile_update: UserProfileUpdate,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rbac_check = Depends(require_users_me_write)
):
    """
    Update current user's profile information
    
    **Requires user profile write permission**
    """
    try:
        profile = current_user["profile"]
        supabase_user = current_user["supabase_user"]
        
        if profile_update.username and profile_update.username != profile.username:
            existing_user = await db.execute(
                select(UserProfile).where(
                    and_(
                        UserProfile.username == profile_update.username,
                        UserProfile.id != profile.id
                    )
                )
            )
            if existing_user.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Username already taken"                )
        
        update_data = profile_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(profile, field, value)
        
        profile.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(profile)
        
        return UserProfileResponse(
            id=str(profile.id),
            user_id=str(profile.user_id),
            username=profile.username,
            email=supabase_user.email,  
            first_name=profile.first_name,
            last_name=profile.last_name,
            display_name=profile.display_name,
            bio=profile.bio,
            avatar_url=profile.avatar_url,
            date_of_birth=profile.date_of_birth,
            timezone=profile.timezone,
            language=profile.language,
            account_type=profile.account_type,
            is_verified=profile.is_verified,
            github_username=profile.github_username,
            twitter_handle=profile.twitter_handle,
            resume_url=profile.resume_url,
            preferences=profile.preferences,
            created_at=profile.created_at,
            updated_at=profile.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user profile: {str(e)}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Operation failed", "code": "PROFILE_UPDATE_FAILED"}
        )

@router.post("/me/profile-image", response_model=ProfileImageUpload)
async def upload_profile_image(
    file: UploadFile = File(..., description="Profile image file (JPEG, PNG, GIF, or WebP, max 5MB)"),
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload a new profile image
    
    Accepts image files in the following formats:
    - JPEG (.jpg, .jpeg)
    - PNG (.png) 
    - GIF (.gif)
    - WebP (.webp)
    
    Maximum file size: 5MB
    """
    try:
        profile = current_user["profile"]
        
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file uploaded"
            )
        
        if profile.avatar_url:
            await user_helpers.delete_profile_image(profile.avatar_url)
        
        image_url = await user_helpers.upload_profile_image(str(profile.id), file)
        
        profile.avatar_url = image_url
        profile.updated_at = datetime.utcnow()
        await db.commit()
        
        return ProfileImageUpload(
            avatar_url=image_url,
            message="Profile image uploaded successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading profile image: {str(e)}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Operation failed", "code": "IMAGE_UPLOAD_FAILED"}
        )

@router.delete("/me/profile-image")
async def delete_profile_image(
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete current user's profile image"""
    try:
        profile = current_user["profile"]
        
        if not profile.avatar_url:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No profile image found"
            )
        
        deleted = await user_helpers.delete_profile_image(profile.avatar_url)

        profile.avatar_url = None
        profile.updated_at = datetime.utcnow()
        
        await db.commit()
        
        return {
            "message": "Profile image deleted successfully",
            "storage_deleted": deleted
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting profile image: {str(e)}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Operation failed", "code": "IMAGE_DELETE_FAILED"}
        )
      
@router.post("/toggle-follow", response_model=FollowActionResponse)
async def toggle_follow_user(
    request: FollowUserRequest,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Toggle follow/unfollow status for a user"""
    try:
        follower_id = current_user["supabase_user"].id
        following_id = uuid.UUID(request.user_id)
        
        if follower_id == following_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot follow yourself"
            )
        
        target_user = await db.execute(
            select(Users).where(Users.id == following_id)
        )
        if not target_user.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        existing_result = await db.execute(
            select(UserFollower).where(
                and_(
                    UserFollower.follower_id == follower_id,
                    UserFollower.following_id == following_id
                )
            )
        )
        existing_follow = existing_result.scalar_one_or_none()
        
        if existing_follow:
            await db.delete(existing_follow)
            await db.commit()
            
            return FollowActionResponse(
                success=True,
                message="Successfully unfollowed user",
                is_following=False
            )
        else:
            follow_relationship = UserFollower(
                follower_id=follower_id,
                following_id=following_id
            )
            db.add(follow_relationship)
            await db.commit()
            
            return FollowActionResponse(
                success=True,
                message="Successfully followed user",
                is_following=True
            )
        
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    except Exception as e:
        logger.error(f"Error toggling follow status: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle follow status"
        )


@router.get("/followers", response_model=FollowersResponse)
async def get_followers(
    user_id: Optional[str] = Query(None, description="User ID to get followers for. If not provided, returns current user's followers"),
    skip: int = Query(0, ge=0, description="Number of followers to skip"),
    limit: int = Query(20, ge=1, le=100, description="Number of followers to return"),
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get followers list for a user"""
    try:
        if user_id:
            target_user_id = uuid.UUID(user_id)
        else:
            target_user_id = current_user["supabase_user"].id
        
        result = await db.execute(
            select(
                UserFollower.follower_id,
                UserFollower.created_at,
                UserProfile.username,
                UserProfile.display_name,
                UserProfile.avatar_url
            )
            .join(UserProfile, UserProfile.user_id == UserFollower.follower_id)
            .where(UserFollower.following_id == target_user_id)
            .order_by(UserFollower.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        
        followers = []
        for row in result.all():
            logger.info(f"Row data: follower_id={row.follower_id}, username={row.username}, display_name={row.display_name}, avatar_url={row.avatar_url}")
            
            followers.append(FollowerUser(
                id=str(row.follower_id),
                username=row.username,
                display_name=row.display_name,
                avatar_url=row.avatar_url,
                followed_at=row.created_at
            ))
        
        count_result = await db.execute(
            select(func.count(UserFollower.follower_id))
            .where(UserFollower.following_id == target_user_id)
        )
        total_count = count_result.scalar()
        
        return FollowersResponse(
            followers=followers,
            total_count=total_count
        )
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    except Exception as e:
        logger.error(f"Error getting followers: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get followers"
        )


@router.get("/following", response_model=FollowingResponse)
async def get_following(
    user_id: Optional[str] = Query(None, description="User ID to get following for. If not provided, returns current user's following"),
    skip: int = Query(0, ge=0, description="Number of following to skip"),
    limit: int = Query(20, ge=1, le=100, description="Number of following to return"),
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get following list for a user"""
    try:
        if user_id:
            target_user_id = uuid.UUID(user_id)
        else:
            target_user_id = current_user["supabase_user"].id

        result = await db.execute(
            select(
                UserFollower.following_id,
                UserFollower.created_at,
                UserProfile.username,
                UserProfile.display_name,
                UserProfile.avatar_url
            )
            .join(UserProfile, UserProfile.user_id == UserFollower.following_id)
            .where(UserFollower.follower_id == target_user_id)
            .order_by(UserFollower.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        
        following = []
        for row in result.all():
            logger.info(f"Row data: following_id={row.following_id}, username={row.username}, display_name={row.display_name}, avatar_url={row.avatar_url}")
            
            following.append(FollowerUser(
                id=str(row.following_id),
                username=row.username,
                display_name=row.display_name,
                avatar_url=row.avatar_url,
                followed_at=row.created_at
            ))

        count_result = await db.execute(
            select(func.count(UserFollower.following_id))
            .where(UserFollower.follower_id == target_user_id)
        )
        total_count = count_result.scalar()
        
        return FollowingResponse(
            following=following,
            total_count=total_count
        )
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    except Exception as e:
        logger.error(f"Error getting following: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get following"
        )


@router.get("/follow-stats", response_model=FollowStatsResponse)
async def get_follow_stats(
    user_id: Optional[str] = Query(None, description="User ID to get stats for. If not provided, returns current user's stats"),
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get follower/following statistics for a user"""
    try:
        if user_id:
            target_user_id = uuid.UUID(user_id)
        else:
            target_user_id = current_user["supabase_user"].id
        
        current_user_id = current_user["supabase_user"].id

        followers_result = await db.execute(
            select(func.count(UserFollower.follower_id))
            .where(UserFollower.following_id == target_user_id)
        )
        followers_count = followers_result.scalar()

        following_result = await db.execute(
            select(func.count(UserFollower.following_id))
            .where(UserFollower.follower_id == target_user_id)
        )
        following_count = following_result.scalar()
        
        stats = FollowStatsResponse(
            followers_count=followers_count,
            following_count=following_count
        )
        
        if target_user_id != current_user_id:
            is_following_result = await db.execute(
                select(exists().where(
                    and_(
                        UserFollower.follower_id == current_user_id,
                        UserFollower.following_id == target_user_id
                    )
                ))
            )
            stats.is_following = is_following_result.scalar()
        
        return stats
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    except Exception as e:
        logger.error(f"Error getting follow stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get follow stats"
        )

