FROM alpine:3.20

RUN apk add --no-cache \
        bash \
        iproute2 \
        netcat-openbsd \
        openssh \
        sudo

RUN adduser -D -s /bin/bash scanner \
    && echo "scanner:scannerpass" | chpasswd \
    && mkdir -p /run/sshd

RUN ssh-keygen -A \
    && printf '%s\n' \
        'PasswordAuthentication yes' \
        'PubkeyAuthentication yes' \
        'PermitRootLogin no' \
        'AllowUsers scanner' \
        > /etc/ssh/sshd_config

COPY docker/common/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
