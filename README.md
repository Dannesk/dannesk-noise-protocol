# dannesk-noise-protocol

[![Rust](https://img.shields.io/badge/Rust-2024_edition-000000?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![ci](https://github.com/Dannesk/dannesk-noise-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/Dannesk/dannesk-noise-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-3B3F43)](LICENSE)

The [Noise Protocol Framework](https://noiseprotocol.org/noise.html)'s NK handshake, `Noise_NK_25519_AESGCM_SHA256`, written from the specification on
RustCrypto and dalek primitives. It is the encrypted socket between the
[Dannesk](https://github.com/Dannesk/app) wallet and its server.


## Example

The handshake layer, with both sides in one place:

```rust
use dannesk_noise_protocol::{Error, Initiator, Responder, StaticKey};

fn main() -> Result<(), Error> {
    let server_key = StaticKey::generate();
    let prologue = b"example v1";

    let (client, message_1) =
        Initiator::new(&server_key.public(), prologue).write_message(b"hello")?;

    let (server, payload) = Responder::new(&server_key, prologue).read_message(&message_1)?;
    assert_eq!(payload, b"hello");
    let (mut server_session, message_2) = server.write_message(b"welcome")?;

    let (mut client_session, payload) = client.read_message(&message_2)?;
    assert_eq!(payload, b"welcome");

    let ciphertext = client_session.encrypt(b"ping")?;
    assert_eq!(server_session.decrypt(&ciphertext)?, b"ping");
    Ok(())
}
```

## License

MIT. See [LICENSE](LICENSE).
