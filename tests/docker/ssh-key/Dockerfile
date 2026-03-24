FROM alpine:3.20

RUN apk add --no-cache \
        bash \
        iproute2 \
        netcat-openbsd \
        openssh \
        sudo

RUN adduser -D -s /bin/bash scanner \
    && echo "scanner:scannerpass" | chpasswd \
    && mkdir -p /run/sshd /home/scanner/.ssh

COPY docker/keys/id_ed25519_valid.pub /home/scanner/.ssh/authorized_keys
COPY docker/common/entrypoint.sh /entrypoint.sh

RUN ssh-keygen -A \
    && printf '%s\n' \
        'PasswordAuthentication no' \
        'PubkeyAuthentication yes' \
        'PermitRootLogin no' \
        'AllowUsers scanner' \
        'AuthorizedKeysFile .ssh/authorized_keys' \
        > /etc/ssh/sshd_config \
    && chown -R scanner:scanner /home/scanner/.ssh \
    && chmod 700 /home/scanner/.ssh \
    && chmod 600 /home/scanner/.ssh/authorized_keys \
    && chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
