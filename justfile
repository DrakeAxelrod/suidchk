
# rustup target add x86_64-unknown-linux-musl
# cargo build --target=x86_64-unknown-linux-musl
run:
  cargo run

setup:
  rustup target add x86_64-unknown-linux-musl

build:
  cargo build --target=x86_64-unknown-linux-musl --release
