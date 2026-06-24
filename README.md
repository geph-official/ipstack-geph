# IpStack-Geph

A fork of [narrowlink/ipstack](https://github.com/narrowlink/ipstack). Main changes:

- Not tightly coupled to TUN interfaces. Instead, packets are passed in and out of the stack in a generic fashion using channels.
- Built on `tokio`: the background processing loop is spawned onto the `tokio` runtime and the streams implement the `tokio` I/O traits (`tokio::io::{AsyncRead, AsyncWrite}`). `IpStack::new` must be called from within a `tokio` runtime.
