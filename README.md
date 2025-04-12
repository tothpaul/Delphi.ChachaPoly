# Delphi.ChachaPoly
Delphi translation of C code by Daniel J. Bernstein

based on https://github.com/grigorig/chachapoly

# ChaChaPoly

This is an RFC 7539 compliant ChaCha20-Poly1305 AEAD implementation. The underlying ChaCha20 implementation used is the original implementation from D. J. Bernstein with changes to the nonce/counter split as required by RFC7539. The Poly1305 implementation is poly1305-donna.

The AEAD code has been designed to be as simple, easy to understand and small as possible. That means no particular architecture specific optimizations are included. The ChaCha20 and Poly1305 implementations were also chosen with this in mind.

An additional AEAD construction is included that reuses 32 byte of keystream that are otherwise thrown away for encryption or decryption of small messages. Use this at your own risk!

# License

The chachapoly code is MIT licensed. The underlying chacha20 implementation by D.J. Bernstein is public domain. The poly1305 implementation used, donna-poly1305, is public domain or MIT licensed (at your own choice). In conclusion, you should consider the combined work MIT licensed.