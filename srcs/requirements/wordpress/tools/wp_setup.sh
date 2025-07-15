#!/bin/bash

if ! wp core is-installed --path=/var/www/html/wordpress --allow-root; then
    echo "🚀 WordPress indiriliyor..."
    wp core download --path=/var/www/html/wordpress --allow-root

    echo "🔧 wp-config.php oluşturuluyor..."
    wp config create --path=/var/www/html/wordpress --allow-root \
        --dbname=$DB_DATABASE \
        --dbhost=$DB_HOST \
        --dbprefix=wp_ \
        --dbuser=$DB_USER_NAME \
        --dbpass=$DB_USERPASS

    wp core install --path=/var/www/html/wordpress --allow-root \
        --url=$DOMAIN \
        --title="$WP_TITLE" \
        --admin_user=$WP_ADMIN_NAME \
        --admin_password=$WP_ADMINPASS \
        --admin_email=$WP_ADMIN_MAIL

    wp plugin update --path=/var/www/html/wordpress --allow-root --all

    wp user create --path=/var/www/html/wordpress --allow-root \
        $WP_USER_NAME $WP_USER_MAIL \
        --user_pass=$WP_USERPASS

    chown www-data:www-data /var/www/html/wordpress/wp-content/uploads --recursive
    mkdir -p /run/php/

    # Otomatik WordPress kurulumu (wp-cli yoksa elle yapılmalı)
    echo "✅ WordPress yapılandırması tamamlandı."
else
    echo "📂 WordPress zaten kurulmuş."
fi

php-fpm8.2 -F
