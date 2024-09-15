#!/bin/sh

sleep 30
python3 -m flask db init
python3 -m flask db migrate
python3 -m flask db upgrade
gunicorn --bind 0.0.0.0:5000 app:app
