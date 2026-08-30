FROM postgres:17
COPY pg-target-init.sh /docker-entrypoint-initdb.d/10-tls-roles.sh
RUN chmod +x /docker-entrypoint-initdb.d/10-tls-roles.sh
