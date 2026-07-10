#!/bin/sh
set -e

echo "Waiting for Redis on redis:6379..."

while ! nc -z redis 6379; do
  sleep 1
done

echo "Redis is ready!"
exec "$@"
