FROM archlinux

WORKDIR /

COPY ./target/release/server /server

ENTRYPOINT ["/server"]
