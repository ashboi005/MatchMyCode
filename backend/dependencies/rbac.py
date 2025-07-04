"""
RBAC dependencies for FastAPI routes
Role-based access control implemented as dependencies that run after authentication
"""
from fastapi import Depends, HTTPException, status, Request
from typing import Dict, Any
import logging

from routers.auth.auth import get_current_user

logger = logging.getLogger(__name__)

RESOURCES_FOR_ROLES = {
    'ADMIN': {
        # Full administrative access
        'admin': ['read', 'write', 'update', 'delete', 'manage'],
        'admin/users': ['read', 'write', 'update', 'delete'],
        'admin/projects': ['read', 'write', 'update', 'delete'],
        'admin/stats': ['read'],
        'admin/reports': ['read', 'write'],
        
        # Moderation capabilities
        'moderation': ['read', 'write', 'update', 'delete', 'manage'],
        'moderation/role-requests': ['read', 'write', 'update', 'delete'],
        'moderation/user-verification': ['read', 'write', 'update'],
        'moderation/content': ['read', 'write', 'update', 'delete'],
        
        # User management
        'users': ['read', 'write', 'update', 'delete'],
        'users/me': ['read', 'write', 'update'],
        'users/profiles': ['read', 'write', 'update', 'delete'],
        'users/follow': ['read', 'write', 'delete'],
        
        # Project management
        'projects': ['read', 'write', 'update', 'delete', 'manage'],
        'projects/members': ['read', 'write', 'update', 'delete'],
        
        # Organizer capabilities
        'events': ['read', 'write', 'update', 'delete', 'manage'],
        'events/participants': ['read', 'write', 'update', 'delete'],
        
        # Recruiter capabilities
        'jobs': ['read', 'write', 'update', 'delete', 'manage'],
        'jobs/applications': ['read', 'write', 'update', 'delete']
    },
    'MODERATOR': {
        # Moderation capabilities
        'moderation': ['read', 'write', 'update'],
        'moderation/role-requests': ['read', 'write', 'update'],
        'moderation/user-verification': ['read', 'write', 'update'],
        'moderation/content': ['read', 'write', 'update', 'delete'],
        
        # Limited user management
        'users': ['read'],
        'users/me': ['read', 'write', 'update'],
        'users/profiles': ['read', 'update'],
        'users/follow': ['read', 'write', 'delete'],
        
        # Project viewing and content moderation
        'projects': ['read', 'update'],
        'projects/members': ['read'],
        
        # Read access to events and jobs for moderation
        'events': ['read', 'update'],
        'jobs': ['read', 'update']
    },
    'ORGANISER': {
        # Event management
        'events': ['read', 'write', 'update', 'delete'],
        'events/participants': ['read', 'write', 'update', 'delete'],
        
        # User interactions
        'users/me': ['read', 'write', 'update'],
        'users/profiles': ['read'],
        'users/follow': ['read', 'write', 'delete'],
        
        # Project viewing
        'projects': ['read', 'write', 'update'],
        'projects/members': ['read', 'write'],
        
        # Limited job viewing
        'jobs': ['read']
    },
    'RECRUITER': {
        # Job management
        'jobs': ['read', 'write', 'update', 'delete'],
        'jobs/applications': ['read', 'write', 'update', 'delete'],
        
        # User profile viewing for recruitment
        'users': ['read'],
        'users/me': ['read', 'write', 'update'],
        'users/profiles': ['read'],
        'users/follow': ['read', 'write', 'delete'],
        
        # Project viewing for talent scouting
        'projects': ['read'],
        'projects/members': ['read'],
        
        # Event viewing
        'events': ['read']
    },
    'USER': {
        # Basic user capabilities
        'users/me': ['read', 'write', 'update'],
        'users/profiles': ['read'],
        'users/follow': ['read', 'write', 'delete'],
        
        # Project management (own projects)
        'projects': ['read', 'write', 'update', 'delete'],
        'projects/members': ['read', 'write'],
        
        # Event participation
        'events': ['read', 'write'],
        'events/participants': ['read', 'write'],
        
        # Job applications
        'jobs': ['read'],
        'jobs/applications': ['read', 'write', 'update']
    }
}

def normalize_path(path: str) -> str:
    """Normalize request path for RBAC checking"""    
    if path.startswith('/'):
        path = path[1:]

    segments = path.split('/')
    
    if len(segments) == 0:
        return path
    
    # Admin routes
    if segments[0] == 'admin':
        if len(segments) >= 2:
            if segments[1] == 'users':
                return 'admin/users'
            elif segments[1] == 'projects':
                return 'admin/projects'
            elif segments[1] == 'stats':
                return 'admin/stats'
            elif segments[1] == 'reports':
                return 'admin/reports'
        return 'admin'
    
    # Moderation routes
    elif segments[0] == 'moderation':
        if len(segments) >= 2:
            if segments[1] == 'role-requests':
                return 'moderation/role-requests'
            elif segments[1] == 'user-verification':
                return 'moderation/user-verification'
            elif segments[1] == 'content':
                return 'moderation/content'
        return 'moderation'
    
    # User routes
    elif segments[0] == 'users':
        if len(segments) >= 2:
            if segments[1] == 'me':
                return 'users/me'
            elif segments[1] == 'profiles' or segments[1].startswith('profile'):
                return 'users/profiles'
            elif segments[1] == 'follow' or 'follow' in segments:
                return 'users/follow'
        return 'users'
    
    # Project routes
    elif segments[0] == 'projects':
        if len(segments) >= 2:
            if segments[1] == 'members' or 'member' in segments:
                return 'projects/members'
        return 'projects'
    
    # Event routes
    elif segments[0] == 'events':
        if len(segments) >= 2:
            if segments[1] == 'participants' or 'participant' in segments:
                return 'events/participants'
        return 'events'
    
    # Job routes
    elif segments[0] == 'jobs':
        if len(segments) >= 2:
            if segments[1] == 'applications' or 'application' in segments:
                return 'jobs/applications'
        return 'jobs'
    
    return segments[0]

def translate_method_to_action(method: str) -> str:
    """Map HTTP methods to RBAC actions"""
    method_permission_mapping = {
        'GET': 'read',
        'POST': 'write',
        'PUT': 'update',
        'PATCH': 'update',
        'DELETE': 'delete',
    }
    return method_permission_mapping.get(method.upper(), 'read')

def has_permission(user_role: str, resource_name: str, required_permission: str) -> bool:
    """Check if user role has permission for the resource and action"""
    if user_role not in RESOURCES_FOR_ROLES:
        return False
    
    user_permissions = RESOURCES_FOR_ROLES[user_role]
    
    # Check exact resource match
    if resource_name in user_permissions:
        return required_permission in user_permissions[resource_name]
    
    # Check parent resource match
    parent_resource = resource_name.split('/')[0] if '/' in resource_name else resource_name
    if parent_resource in user_permissions:
        return required_permission in user_permissions[parent_resource]
    
    return False

def require_permission(resource: str = None, permission: str = None):
    """
    Create an RBAC dependency that checks permissions
    Args:
        resource: Specific resource name (auto-detected if not provided)
        permission: Specific permission (auto-detected if not provided)
    """
    def check_rbac(request: Request):
        """RBAC dependency function"""
        try:
            current_user = getattr(request.state, 'current_user', None)
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )

            user_role = current_user.get('role', 'USER') 
            
            resource_name = resource or normalize_path(str(request.url.path))
            required_permission = permission or translate_method_to_action(request.method)
            
            logger.info(f"RBAC Check - User: {user_role}, Resource: {resource_name}, Permission: {required_permission}")
            
            if not has_permission(user_role, resource_name, required_permission):
                logger.warning(f"Access denied - User: {user_role}, Resource: {resource_name}, Permission: {required_permission}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied. {user_role.title()} role does not have {required_permission} permission for {resource_name}"
                )
            
            logger.info(f"Access granted - User: {user_role}, Resource: {resource_name}, Permission: {required_permission}")
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"RBAC dependency error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authorization check failed"
            )
    
    return check_rbac

def require_role(*allowed_roles):
    """
    Create a simple role-based dependency
    Args:
        allowed_roles: Roles that are allowed to access the endpoint
    """
    def check_role(current_user = Depends(get_current_user)):
        """Role checking dependency function"""
        try:
            # Extract user role from the new current_user structure
            user_role = current_user.get('role', 'USER')  # default fallback
            
            if user_role not in allowed_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied. Required roles: {', '.join(allowed_roles)}. Current role: {user_role}"
                )
            
            return current_user
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Role check error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Role authorization check failed"
            )
    
    return check_role

# Common permission dependencies for easy use

# Admin permissions
require_admin_read = require_permission("admin", "read")
require_admin_write = require_permission("admin", "write")
require_admin_manage = require_permission("admin", "manage")
require_admin_users = require_permission("admin/users", "read")
require_admin_users_write = require_permission("admin/users", "write")
require_admin_users_delete = require_permission("admin/users", "delete")
require_admin_projects = require_permission("admin/projects", "read")
require_admin_projects_write = require_permission("admin/projects", "write")
require_admin_stats = require_permission("admin/stats", "read")
require_admin_reports = require_permission("admin/reports", "read")
require_admin_reports_write = require_permission("admin/reports", "write")

# Moderation permissions
require_moderation_read = require_permission("moderation", "read")
require_moderation_write = require_permission("moderation", "write")
require_moderation_role_requests = require_permission("moderation/role-requests", "read")
require_moderation_role_requests_write = require_permission("moderation/role-requests", "write")
require_moderation_role_requests_update = require_permission("moderation/role-requests", "update")
require_moderation_user_verification = require_permission("moderation/user-verification", "read")
require_moderation_user_verification_write = require_permission("moderation/user-verification", "write")
require_moderation_content = require_permission("moderation/content", "read")
require_moderation_content_write = require_permission("moderation/content", "write")
require_moderation_content_delete = require_permission("moderation/content", "delete")

# User permissions
require_users_read = require_permission("users", "read")
require_users_profiles = require_permission("users/profiles", "read")
require_users_me = require_permission("users/me", "read")
require_users_me_write = require_permission("users/me", "write")
require_users_follow = require_permission("users/follow", "read")
require_users_follow_write = require_permission("users/follow", "write")

# Project permissions
require_projects_read = require_permission("projects", "read")
require_projects_write = require_permission("projects", "write")
require_projects_update = require_permission("projects", "update")
require_projects_delete = require_permission("projects", "delete")
require_projects_members = require_permission("projects/members", "read")
require_projects_members_write = require_permission("projects/members", "write")

# Event permissions (for organizers)
require_events_read = require_permission("events", "read")
require_events_write = require_permission("events", "write")
require_events_update = require_permission("events", "update")
require_events_delete = require_permission("events", "delete")
require_events_participants = require_permission("events/participants", "read")
require_events_participants_write = require_permission("events/participants", "write")

# Job permissions (for recruiters)
require_jobs_read = require_permission("jobs", "read")
require_jobs_write = require_permission("jobs", "write")
require_jobs_update = require_permission("jobs", "update")
require_jobs_delete = require_permission("jobs", "delete")
require_jobs_applications = require_permission("jobs/applications", "read")
require_jobs_applications_write = require_permission("jobs/applications", "write")

# Role-based dependencies for common use cases
require_admin_only = require_role("ADMIN")
require_admin_or_moderator = require_role("ADMIN", "MODERATOR")
require_admin_moderator_or_organiser = require_role("ADMIN", "MODERATOR", "ORGANISER")
require_admin_moderator_or_recruiter = require_role("ADMIN", "MODERATOR", "RECRUITER")
require_any_elevated_role = require_role("ADMIN", "MODERATOR", "ORGANISER", "RECRUITER")