# libsodium-ada [![License](http://img.shields.io/badge/license-ISC-green.svg)](https://github.com/jrmarino/libsodium-ada/blob/master/License.txt)

libsodium-ada is a set of thick Ada bindings to
[libsodium](https://github.com/jedisct1/libsodium) thick bindings to libsodium.
libsodium is a portable and relatively easy to use implementation of
[Daniel Bernstein's](http://cr.yp.to/djb.html) fantastic
[NaCl](http://nacl.cr.yp.to/) library.

## Why

NaCl is a great encryption, hashing, and authentication library that is
designed to make proper implementation easy and straight-forward.  By using
it, many of the finer details including speed-optimization are abstracted
away so the programmer doesn't need to worry about them.  NaCl itself is less
than portable C, only targeted for *nix systems.  libsodium makes the library
portable, and adds additional conveniences to make the library easily
standardized across multiple platforms, operating systems, and languages.

Crypto is very tricky to implement correctly.  With the sodium library, you
are much more likely to get it correct out of the box, by implementing solid
encryption standards and practices without materially effecting performance.


## Documentation

The testcases in the examples directory also serve to illustrate how the
bindings can be used.  The
[original libsodium documentation library](http://doc.libsodium.org/) written
by Frank Denis ([@jedisct1](https://github.com/jedisct1)) is also useful.

## Requirements & Versions

libsodium-ada was tested with the 32-bit libsodium.a library version 1.0.10
built for mingw (since GNAT GPL 2016 is 32-bit).
[Click here for precompiled libsodium DLLs.](https://download.libsodium.org/libsodium/releases/)
It will also work with *nix versions.

## License

NaCl has been released to the public domain to avoid copyright issues.
Both libsodium and these bindings have been released under the
[ISC license](https://en.wikipedia.org/wiki/ISC_license).
