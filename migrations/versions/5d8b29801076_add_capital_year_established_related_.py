"""Add capital, year_established, related_countries fields

Revision ID: 5d8b29801076
Revises: b6346fcdff09
Create Date: 2025-04-15 06:52:06.373847

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5d8b29801076'
down_revision = 'b6346fcdff09'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('country', schema=None) as batch_op:
        batch_op.add_column(sa.Column('capital', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('year_established', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('related_countries', sa.Text(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('country', schema=None) as batch_op:
        batch_op.drop_column('related_countries')
        batch_op.drop_column('year_established')
        batch_op.drop_column('capital')

    # ### end Alembic commands ###
