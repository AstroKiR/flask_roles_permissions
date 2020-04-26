"""role table

Revision ID: 756243a987dc
Revises: e063187f2a7c
Create Date: 2020-04-27 01:09:17.736249

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '756243a987dc'
down_revision = 'e063187f2a7c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('permission',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ability', sa.String(length=64), nullable=True),
    sa.Column('creator_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['creator_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('ability')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('permission')
    # ### end Alembic commands ###
