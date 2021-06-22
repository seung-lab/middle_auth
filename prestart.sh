#! /usr/bin/env sh
# Let the DB start
sleep 10;
# Run migrations
python -m flask db upgrade
