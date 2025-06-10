from sqlalchemy import (
    Boolean, 
    String, 
    Text, 
    DateTime, 
    SmallInteger,
    CheckConstraint,
    PrimaryKeyConstraint,
    UniqueConstraint,
    Index,
    Computed,
    text,
    ForeignKey,
    Column
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.ext.declarative import declarative_base
from typing import Optional, List
import uuid

Base = declarative_base()


class Users(Base):
    """
    Supabase auth.users table schema with additional fields
    This mirrors the Supabase authentication table to enable proper foreign key relationships
    """
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "email_change_confirm_status >= 0 AND email_change_confirm_status <= 2",
            name="users_email_change_confirm_status_check",
        ),
        PrimaryKeyConstraint("id", name="users_pkey"),
        UniqueConstraint("phone", name="users_phone_key"),
        Index("confirmation_token_idx", "confirmation_token", unique=True),
        Index(
            "email_change_token_current_idx", "email_change_token_current", unique=True
        ),
        Index("email_change_token_new_idx", "email_change_token_new", unique=True),
        Index("reauthentication_token_idx", "reauthentication_token", unique=True),
        Index("recovery_token_idx", "recovery_token", unique=True),
        Index("users_email_partial_key", "email", unique=True),
        Index("users_instance_id_email_idx", "instance_id"),
        Index("users_instance_id_idx", "instance_id"),
        Index("users_is_anonymous_idx", "is_anonymous"),
        {
            "comment": "Auth: Stores user login data within a secure schema.",
            "schema": "auth",
        },
    )

    # Core fields
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    
    # Authentication fields
    is_sso_user: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        comment="Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.",
    )
    is_anonymous: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    instance_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    aud: Mapped[Optional[str]] = mapped_column(String(255))
    role: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Contact information
    email: Mapped[Optional[str]] = mapped_column(String(255))
    phone: Mapped[Optional[str]] = mapped_column(Text, server_default=text("NULL::character varying"))
    
    # Security fields
    encrypted_password: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Email confirmation
    email_confirmed_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    confirmation_token: Mapped[Optional[str]] = mapped_column(String(255))
    confirmation_sent_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    
    # Password recovery
    recovery_token: Mapped[Optional[str]] = mapped_column(String(255))
    recovery_sent_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    
    # Email change process
    email_change_token_new: Mapped[Optional[str]] = mapped_column(String(255))
    email_change: Mapped[Optional[str]] = mapped_column(String(255))
    email_change_sent_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    email_change_token_current: Mapped[Optional[str]] = mapped_column(
        String(255), server_default=text("''::character varying")
    )
    email_change_confirm_status: Mapped[Optional[int]] = mapped_column(SmallInteger, server_default=text("0"))
    
    # Phone change process
    phone_confirmed_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    phone_change: Mapped[Optional[str]] = mapped_column(Text, server_default=text("''::character varying"))
    phone_change_token: Mapped[Optional[str]] = mapped_column(
        String(255), server_default=text("''::character varying")
    )
    phone_change_sent_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    
    # Sign in tracking
    last_sign_in_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    invited_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    
    # Metadata
    raw_app_meta_data: Mapped[Optional[dict]] = mapped_column(JSONB)
    raw_user_meta_data: Mapped[Optional[dict]] = mapped_column(JSONB)
    
    # Admin and security
    is_super_admin: Mapped[Optional[bool]] = mapped_column(Boolean)
    banned_until: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    
    # Reauthentication
    reauthentication_token: Mapped[Optional[str]] = mapped_column(
        String(255), server_default=text("''::character varying")
    )
    reauthentication_sent_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    
    # Timestamps
    created_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    updated_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    deleted_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    
    # Computed field
    confirmed_at: Mapped[Optional[DateTime]] = mapped_column(
        DateTime(True),
        Computed("LEAST(email_confirmed_at, phone_confirmed_at)", persisted=True),
    )    # Social media and portfolio
    github_username: Mapped[Optional[str]] = mapped_column(String(100), comment="GitHub username")
    twitter_handle: Mapped[Optional[str]] = mapped_column(String(50), comment="Twitter/X handle")
    resume_url: Mapped[Optional[str]] = mapped_column(String(500), comment="URL to resume/CV")
    
    # Relationships
    user_profile: Mapped[Optional["UserProfile"]] = relationship(
        "UserProfile", 
        back_populates="user", 
        uselist=False,
        cascade="all, delete-orphan"
    )
    
    # Follower relationships
    following_relationships: Mapped[List["UserFollower"]] = relationship(
        "UserFollower",
        foreign_keys="UserFollower.follower_id",
        back_populates="follower",
        cascade="all, delete-orphan"
    )
    follower_relationships: Mapped[List["UserFollower"]] = relationship(
        "UserFollower",
        foreign_keys="UserFollower.following_id", 
        back_populates="following",
        cascade="all, delete-orphan"
    )
    
    # Project relationships
    projects: Mapped[List["Project"]] = relationship(
        "Project",
        back_populates="owner",
        cascade="all, delete-orphan",
        foreign_keys="Project.owner_id"
    )
    project_memberships: Mapped[List["ProjectMember"]] = relationship(
        "ProjectMember",
        back_populates="user",
        cascade="all, delete-orphan"
    )


class UserProfile(Base):
    """
    Extended user profile with additional fields
    This extends the basic auth.users table with application-specific data
    """
    __tablename__ = "user_profiles"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), 
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False
    )
    
    # Profile information
    username: Mapped[Optional[str]] = mapped_column(String(100), unique=True, index=True)
    first_name: Mapped[Optional[str]] = mapped_column(String(100))
    last_name: Mapped[Optional[str]] = mapped_column(String(100))
    display_name: Mapped[Optional[str]] = mapped_column(String(100))
    bio: Mapped[Optional[str]] = mapped_column(Text)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500))
    date_of_birth: Mapped[Optional[DateTime]] = mapped_column(DateTime(True))
    timezone: Mapped[Optional[str]] = mapped_column(String(50))
    language: Mapped[Optional[str]] = mapped_column(String(10), default="en")
    
    # Account Type
    account_type: Mapped[Optional[str]] = mapped_column(
        String(50),
        comment="Account Type: Developer/Company/Recruiter/Organizer"
    )
    
    # Educational Details
    college_name: Mapped[Optional[str]] = mapped_column(String(255))
    current_year: Mapped[Optional[int]] = mapped_column(SmallInteger, comment="Current academic year")
    graduation_year: Mapped[Optional[int]] = mapped_column(SmallInteger, comment="Year of graduation")
    course_branch: Mapped[Optional[str]] = mapped_column(String(255), comment="Course/Branch")
    enrollment_number: Mapped[Optional[str]] = mapped_column(String(50))
    
    # Location Details
    address: Mapped[Optional[str]] = mapped_column(Text, comment="Address lines 1 and 2")
    city: Mapped[Optional[str]] = mapped_column(String(100))
    state: Mapped[Optional[str]] = mapped_column(String(100))
    pincode: Mapped[Optional[str]] = mapped_column(String(20))
    country: Mapped[Optional[str]] = mapped_column(String(100))
    
    # Professional Profile
    portfolio_url: Mapped[Optional[str]] = mapped_column(String(500))
    linkedin_url: Mapped[Optional[str]] = mapped_column(String(500))
    years_experience: Mapped[Optional[int]] = mapped_column(SmallInteger)
    current_role: Mapped[Optional[str]] = mapped_column(String(100))
    tech_stack: Mapped[Optional[List[str]]] = mapped_column(JSONB, comment="List of skills/technologies")
    open_to: Mapped[Optional[List[str]]] = mapped_column(
        JSONB, 
        comment="Open to: Freelance, Internships, Full-time, Collaboration"
    )
    
    # Preferences (stored as JSON)
    preferences: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict)
    
    # Timestamps
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(True), 
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(True), 
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
        nullable=False
    )
    
    # Relationship back to auth user
    user: Mapped["Users"] = relationship("Users", back_populates="user_profile")


class UserFollower(Base):
    """
    Many-to-many relationship table for user followers/following
    """
    __tablename__ = "user_followers"
    __table_args__ = (
        PrimaryKeyConstraint("follower_id", "following_id", name="user_followers_pkey"),
        Index("idx_follower_id", "follower_id"),
        Index("idx_following_id", "following_id"),
        CheckConstraint("follower_id != following_id", name="no_self_follow_check"),
    )
    
    follower_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False
    )
    following_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )
    
    # Relationships
    follower: Mapped["Users"] = relationship(
        "Users",
        foreign_keys=[follower_id],
        back_populates="following_relationships"
    )
    following: Mapped["Users"] = relationship(
        "Users", 
        foreign_keys=[following_id],
        back_populates="follower_relationships"
    )


class Project(Base):
    """
    User projects model
    """
    __tablename__ = "projects"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False
    )
    
    # Project details
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    github_link: Mapped[Optional[str]] = mapped_column(String(500))
    demo_link: Mapped[Optional[str]] = mapped_column(String(500))
    tech_stack: Mapped[Optional[List[str]]] = mapped_column(JSONB, comment="Technologies used")
    status: Mapped[Optional[str]] = mapped_column(
        String(50),
        default="Active",
        comment="Project status: Active/Completed/Open to Contributions"
    )
    cover_image_url: Mapped[Optional[str]] = mapped_column(String(500))
    
    # Timestamps
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(True), 
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(True), 
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
        nullable=False
    )
    
    # Relationships
    owner: Mapped["Users"] = relationship("Users", back_populates="projects")
    team_members: Mapped[List["ProjectMember"]] = relationship(
        "ProjectMember",
        back_populates="project",
        cascade="all, delete-orphan"
    )


class ProjectMember(Base):
    """
    Many-to-many relationship between projects and users (team members)
    """
    __tablename__ = "project_members"
    __table_args__ = (
        PrimaryKeyConstraint("project_id", "user_id", name="project_members_pkey"),
    )
    
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False
    )
    role: Mapped[Optional[str]] = mapped_column(String(100), comment="Role in project")
    
    # Timestamps
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(True), 
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(True), 
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
        nullable=False
    )
    
    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="team_members")
    user: Mapped["Users"] = relationship("Users", back_populates="project_memberships")