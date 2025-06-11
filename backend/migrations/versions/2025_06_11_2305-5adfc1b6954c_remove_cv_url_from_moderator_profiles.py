"""remove_cv_url_from_moderator_profiles

Revision ID: 5adfc1b6954c
Revises: 71b207445b69
Create Date: 2025-06-11 23:05:13.792748

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5adfc1b6954c'
down_revision: Union[str, None] = '71b207445b69'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove cv_url column from moderator_profiles table
    op.drop_column('moderator_profiles', 'cv_url')


def downgrade() -> None:
    # Add back cv_url column to moderator_profiles table
    op.add_column('moderator_profiles', sa.Column('cv_url', sa.String(length=500), nullable=False, comment='PDF of resume/CV'))
