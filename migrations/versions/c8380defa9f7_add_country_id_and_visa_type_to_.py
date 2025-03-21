"""Add country_id and visa_type to VisaApplication

Revision ID: c8380defa9f7
Revises: 2564fba35694
Create Date: 2024-12-23 18:39:03.184379

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c8380defa9f7'
down_revision = '2564fba35694'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('visa_application', schema=None) as batch_op:
        batch_op.add_column(sa.Column('country_id', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('visa_type', sa.String(length=50), nullable=False))
        batch_op.add_column(sa.Column('passport_number', sa.String(length=20), nullable=False))
        batch_op.create_foreign_key(None, 'country', ['country_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('visa_application', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('passport_number')
        batch_op.drop_column('visa_type')
        batch_op.drop_column('country_id')

    # ### end Alembic commands ###
