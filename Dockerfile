ADD file:54d82a3a8fe8d47aaa58650783f2a7198891e89ca95d6e7455f8999651c2fc98 in /
CMD ["bash"]
MAINTAINER NGINX Docker Maintainers "docker-maint@nginx.com"
ENV NGINX_VERSION=1.13.2-1~stretch
ENV NJS_VERSION=1.13.2.0.1.11-1~stretch
MAINTAINER /bin/sh -c apt-get update 	\
    && apt-get install --no-install-recommends --no-install-suggests -y gnupg1 	\
    && 	NGINX_GPGKEY=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62; 	found=''; 	for server in 		ha.pool.sks-keyservers.net 		hkp://keyserver.ubuntu.com:80 		hkp://p80.pool.sks-keyservers.net:80 		pgp.mit.edu 	; do 		echo "Fetching GPG key $NGINX_GPGKEY from $server"; 		apt-key adv --keyserver "$server" --keyserver-options timeout=10 --recv-keys "$NGINX_GPGKEY" \
    && found=yes \
    && break; 	done; 	test -z "$found" \
    && echo >&2 "error: failed to fetch GPG key $NGINX_GPGKEY" \
    && exit 1; 	apt-get remove --purge -y gnupg1 \
    && apt-get -y --purge autoremove \
    && rm -rf /var/lib/apt/lists/* 	\
    && echo "deb http://nginx.org/packages/mainline/debian/ stretch nginx" >> /etc/apt/sources.list 	\
    && apt-get update 	\
    && apt-get install --no-install-recommends --no-install-suggests -y 						nginx=${NGINX_VERSION} 						nginx-module-xslt=${NGINX_VERSION} 						nginx-module-geoip=${NGINX_VERSION} 						nginx-module-image-filter=${NGINX_VERSION} 						nginx-module-njs=${NJS_VERSION} 						gettext-base 	\
    && rm -rf /var/lib/apt/lists/*
MAINTAINER /bin/sh -c ln -sf /dev/stdout /var/log/nginx/access.log 	\
    && ln -sf /dev/stderr /var/log/nginx/error.log
EXPOSE 80/tcp
STOPSIGNAL [SIGTERM]
CMD ["nginx" "-g" "daemon off;"]
MAINTAINER phithon <root@leavesongs.com>