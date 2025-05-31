#!/bin/bash

set -e

mysqld_safe --datadir="/var/lib/mysql" &

# MariaDB'nin hazır olmasını bekle (maksimum 60 saniye)
for i in {1..30}; do
  if mysqladmin ping --silent; then
    echo "MariaDB is up!"
    break
  fi
  echo "Waiting for MariaDB to be ready... ($i)"
  sleep 2
done

# Root şifresi ayarlanmış mı kontrol et
if mysql -u root -e "SELECT 1;" 2>/dev/null; then
  echo "Root password not set, setting now..."
  mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOTPASS}';
FLUSH PRIVILEGES;
EOF
else
  echo "Root password already set or cannot connect without password."
fi

# Artık şifreli bağlan
if ! mysql -u root -p"${DB_ROOTPASS}" -e "SELECT 1;"; then
  echo "ERROR: Cannot connect to MariaDB with root password. Exiting." >&2
  exit 1
fi

echo "Creating database and user if not exists..."
mysql -u root -p"${DB_ROOTPASS}" <<EOF
CREATE DATABASE IF NOT EXISTS \`${DB_DATABASE}\`;
CREATE USER IF NOT EXISTS '${DB_USER_NAME}'@'%' IDENTIFIED BY '${DB_USERPASS}';
GRANT ALL PRIVILEGES ON \`${DB_DATABASE}\`.* TO '${DB_USER_NAME}'@'%';
FLUSH PRIVILEGES;
EOF

echo "MariaDB init finished, waiting for foreground..."
wait