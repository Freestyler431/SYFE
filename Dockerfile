FROM php:8.2-apache

# Install system dependencies and PHP extensions
RUN apt-get update && apt-get install -y 
    libmariadb-dev 
    && docker-php-ext-install pdo_mysql 
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html

# Copy project files
COPY . /var/www/html/

# Create storage directory and set permissions
RUN mkdir -p /var/www/html/storage/chunks && 
    chown -R www-data:www-data /var/www/html/storage && 
    chmod -R 755 /var/www/html/storage

# Expose port 80
EXPOSE 80
