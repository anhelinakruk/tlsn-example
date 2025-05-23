# How to Run

## Step 0: Run the Server

Start the server from this example:
https://github.com/tlsnotary/tlsn/tree/dev/crates/server-fixture/server

```bash
PORT=4000 cargo run --bin tlsn-server-fixture
```

## Step 1: Run the Verifier

Start the verifier first in a terminal:

```bash
cargo run --bin verifier
```

## Step 2: Run the Prover

In a separate terminal, run the prover:

```bash
cargo run --bin prover
```
