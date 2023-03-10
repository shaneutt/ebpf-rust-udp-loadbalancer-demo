FROM rust as builder

WORKDIR /workspace

COPY . .

RUN cargo build --release

FROM archlinux

WORKDIR /

COPY --from=builder /workspace/target/debug/demo-server /demo-server

ENTRYPOINT ["/demo-server"]
