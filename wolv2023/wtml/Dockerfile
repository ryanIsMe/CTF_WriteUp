FROM ubuntu:20.04@sha256:b39db7fc56971aac21dee02187e898db759c4f26b9b27b1d80b6ad32ff330c76 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user

COPY challenge /home/user/

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

COPY --from=chroot / /chroot

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail /bin/sh"
