"""api key multple

Revision ID: 9451e1b711f4
Revises: 0dfa3ff7c781
Create Date: 2022-11-03 12:02:08.520858

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9451e1b711f4'
down_revision = '0dfa3ff7c781'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('api_key', sa.Column('created', sa.DateTime(), server_default=sa.text('now()'), nullable=True))
    op.add_column('api_key', sa.Column('updated', sa.DateTime(), server_default=sa.text('now()'), nullable=True))
    op.drop_constraint('api_key_user_id_key', 'api_key', type_='unique')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint('api_key_user_id_key', 'api_key', ['user_id'])
    op.drop_column('api_key', 'updated')
    op.drop_column('api_key', 'created')
    # ### end Alembic commands ###
