#!/bin/sh
set -eu

flask --app secretshield:create_app db upgrade
flask --app secretshield:create_app bootstrap-admin
exec gunicorn --bind="0.0.0.0:${PORT:-5000}" --workers=1 --timeout=120 'secretshield:create_app()'
