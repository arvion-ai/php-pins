# syntax=docker/dockerfile:1
ARG PHP_VERSION=8.1
FROM php:${PHP_VERSION}-fpm-alpine AS base
RUN docker-php-ext-install pdo_mysql
FROM base AS app
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
FROM composer:2 AS deps
FROM scratch
