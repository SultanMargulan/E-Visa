"""Add VisaApplication model

Revision ID: 2564fba35694
Revises: 3c4678bd603a
Create Date: 2024-12-23 18:21:12.123359

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2564fba35694'
down_revision = '3c4678bd603a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('visa_application',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('application_status', sa.String(length=50), nullable=False),
    sa.Column('submitted_at', sa.DateTime(), nullable=False),
    sa.Column('last_updated_at', sa.DateTime(), nullable=False),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('visa_application')
    # ### end Alembic commands ###
