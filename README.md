# IpStack-Geph

A fork of [narrowlink/ipstack](https://github.com/narrowlink/ipstack). Main changes:

- Not tightly coupled to TUN interfaces. Instead, packets are passed in and out of the stack in a generic fashion using channels.
- De-`tokio`-ified, like the rest of the Geph package ecosystem. Does not use the `tokio` executor and implenets `futures` I/O traits.
