FROM debian:bookworm-slim

RUN apt-get update -y && apt-get install -y \
    dumb-init mariadb-server mariadb-client \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# MariaDB dizinlerini oluştur ve izinleri ayarla
RUN mkdir -p /var/run/mysqld \
    && chown -R mysql:mysql /var/run/mysqld \
    && chown -R mysql:mysql /var/lib/mysql

COPY ./conf/mariadb.cnf /etc/mysql/mariadb.conf.d/50-server.cnf

COPY ./tools/sql_start.sh /tmp/
RUN chmod +x /tmp/sql_start.sh

EXPOSE 3306

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/bin/bash", "/tmp/sql_start.sh"]
