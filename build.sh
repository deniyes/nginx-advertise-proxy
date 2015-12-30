#!/bin/bash

tar zxvf nginx-1.6.0.tar.gz
patch  -p0  < https.patch

cd nginx-1.6.0/
#CFLAGS="-g -O0" ./configure --prefix=/etc/nginx \
./configure --prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx  \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log  \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/var/run/nginx.pid  \
--lock-path=/var/run/nginx.lock  \
--user=nginx --group=nginx  \
--with-http_realip_module \
--with-http_addition_module \
--with-http_sub_module  \
--with-http_dav_module  \
--with-http_flv_module  \
--with-http_mp4_module   \
--with-http_gzip_static_module  \
--with-http_random_index_module  \
--with-http_secure_link_module  \
--with-http_stub_status_module   \
--with-file-aio   \
--add-module=../add_modules/advertise_inject \
--add-module=../add_modules/http_gunzip \
--add-module=../add_modules/https_continue \
--add-module=../add_modules/proxy_connect \
--add-module=../add_modules/limit_traffic_rate \
--add-module=../add_modules/rewrite_request_body

make
