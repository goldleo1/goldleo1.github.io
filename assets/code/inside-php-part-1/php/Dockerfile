FROM php:8.2-fpm

WORKDIR /var/www/html

RUN docker-php-ext-install mysqli pdo pdo_mysql

COPY ./index.php /var/www/html/index.php
COPY ./phpinfo.php /var/www/html/phpinfo.php

EXPOSE 9000
CMD ["php-fpm"]
