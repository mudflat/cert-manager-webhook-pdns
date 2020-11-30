FROM alpine:edge

RUN apk add --update-cache \
    pdns pdns-backend-sqlite3 \
    && rm -rf /var/cache/apk/*

COPY . /pdns-mock

RUN mkdir -p /var/lib/powerdns && \
    cat /pdns-mock/pdns.sql | sqlite3 /var/lib/powerdns/pdns.db && \ 
    cat /pdns-mock/example.sql | sqlite3 /var/lib/powerdns/pdns.db && \ 
    cp /pdns-mock/pdns.conf /etc/pdns/pdns.conf && \
    chown -R pdns:pdns /var/lib/powerdns/ && \
    chmod a+rw /var/lib/powerdns/pdns.db
EXPOSE 8081 53 53/udp

CMD [ "/usr/sbin/pdns_server","--config-dir=/etc/pdns/"]