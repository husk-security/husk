#![forbid(unsafe_code)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Rust ignores SIGPIPE at startup, so a closed downstream pipe surfaces as
    // an EPIPE write error that `println!` turns into a panic. Restoring the
    // default disposition makes `husk ... | head` end the way every other Unix
    // command does.
    sigpipe::reset();
    husk::cli::run().await
}
