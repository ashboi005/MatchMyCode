"""
Project routes with RBAC implementation
Example showing how to use the RBAC system
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from config import get_db
from models import Project, ProjectMember, UserProfile
from routers.auth.auth import get_current_user
from dependencies.rbac import (
    require_projects_read,
    require_projects_write,
    require_projects_update,
    require_projects_delete,
    require_projects_members,
    require_projects_members_write,
    require_admin_projects,
    require_permission
)
from typing import Optional, List
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/projects", tags=["Projects"])

@router.get("/", response_model=List[dict])
async def list_projects(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    tech_stack: Optional[str] = Query(None, description="Filter by technology"),
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rbac_check = Depends(require_projects_read)
):
    """
    Get paginated list of projects
    
    **Requires project read permission**
    
    - **page**: Page number
    - **page_size**: Items per page
    - **tech_stack**: Filter by technology
    - **status**: Filter by project status
    """
    try:
        query = select(Project).order_by(Project.created_at.desc())
        
        if tech_stack:
            query = query.where(Project.tech_stack.contains([tech_stack]))
        if status:
            query = query.where(Project.status == status)
        
        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)
        
        result = await db.execute(query)
        projects = result.scalars().all()
        
        return [
            {
                "id": str(project.id),
                "title": project.title,
                "description": project.description,
                "tech_stack": project.tech_stack,
                "status": project.status,
                "created_at": project.created_at,
                "owner_id": str(project.owner_id)
            }
            for project in projects
        ]
        
    except Exception as e:
        logger.error(f"Error fetching projects: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch projects"
        )

@router.post("/", response_model=dict)
async def create_project(
    project_data: dict,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rbac_check = Depends(require_projects_write)
):
    """
    Create a new project
    
    **Requires project write permission**
    """
    try:
        user_id = current_user["profile"].user_id
        
        new_project = Project(
            owner_id=user_id,
            title=project_data.get("title"),
            description=project_data.get("description"),
            tech_stack=project_data.get("tech_stack", []),
            status=project_data.get("status", "Active")
        )
        
        db.add(new_project)
        await db.commit()
        await db.refresh(new_project)
        
        return {
            "id": str(new_project.id),
            "title": new_project.title,
            "description": new_project.description,
            "tech_stack": new_project.tech_stack,
            "status": new_project.status,
            "created_at": new_project.created_at,
            "owner_id": str(new_project.owner_id)
        }
        
    except Exception as e:
        logger.error(f"Error creating project: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create project"
        )

@router.put("/{project_id}", response_model=dict)
async def update_project(
    project_id: str,
    project_data: dict,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rbac_check = Depends(require_projects_update)
):
    """
    Update a project
    
    **Requires project update permission**
    
    Users can only update their own projects unless they have elevated permissions
    """
    try:
        project_uuid = uuid.UUID(project_id)
        user_id = current_user["profile"].user_id
        user_role = current_user["profile"].account_type
        
        result = await db.execute(
            select(Project).where(Project.id == project_uuid)
        )
        project = result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )

        if project.owner_id != user_id and user_role not in ["ADMIN", "MODERATOR"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update your own projects"
            )
        
        for field, value in project_data.items():
            if hasattr(project, field):
                setattr(project, field, value)
        
        project.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(project)
        
        return {
            "id": str(project.id),
            "title": project.title,
            "description": project.description,
            "tech_stack": project.tech_stack,
            "status": project.status,
            "updated_at": project.updated_at,
            "owner_id": str(project.owner_id)
        }
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid project ID"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating project: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update project"
        )

@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rbac_check = Depends(require_projects_delete)
):
    """
    Delete a project
    
    **Requires project delete permission**
    
    Users can only delete their own projects unless they have elevated permissions
    """
    try:
        project_uuid = uuid.UUID(project_id)
        user_id = current_user["profile"].user_id
        user_role = current_user["profile"].account_type
        
        result = await db.execute(
            select(Project).where(Project.id == project_uuid)
        )
        project = result.scalar_one_or_none()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )

        if project.owner_id != user_id and user_role not in ["ADMIN", "MODERATOR"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own projects"
            )
        
        await db.delete(project)
        await db.commit()
        
        return {"message": "Project deleted successfully"}
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid project ID"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting project: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete project"
        )

@router.get("/admin/all", response_model=List[dict])
async def admin_list_all_projects(
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rbac_check = Depends(require_admin_projects)
):
    """
    Admin-only endpoint to list all projects with additional details
    
    **Requires admin projects permission**
    """
    try:
        query = select(Project).order_by(Project.created_at.desc())
        result = await db.execute(query)
        projects = result.scalars().all()
        
        return [
            {
                "id": str(project.id),
                "title": project.title,
                "description": project.description,
                "tech_stack": project.tech_stack,
                "status": project.status,
                "created_at": project.created_at,
                "updated_at": project.updated_at,
                "owner_id": str(project.owner_id)
            }
            for project in projects
        ]
        
    except Exception as e:
        logger.error(f"Error fetching all projects: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch projects"
        )

@router.get("/{project_id}/members")
async def get_project_members(
    project_id: str,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rbac_check = Depends(require_projects_members)
):
    """
    Get project members
    
    **Requires project members read permission**
    """
    try:
        project_uuid = uuid.UUID(project_id)
        
        query = select(ProjectMember, UserProfile).join(
            UserProfile, ProjectMember.user_id == UserProfile.user_id
        ).where(ProjectMember.project_id == project_uuid)
        
        result = await db.execute(query)
        members = result.all()
        
        return [
            {
                "user_id": str(member.ProjectMember.user_id),
                "role": member.ProjectMember.role,
                "username": member.UserProfile.username,
                "display_name": member.UserProfile.display_name,
                "joined_at": member.ProjectMember.created_at
            }
            for member in members
        ]
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid project ID"
        )
    except Exception as e:
        logger.error(f"Error fetching project members: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch project members"
        )
