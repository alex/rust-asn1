rust-asn1
=========

.. image:: https://travis-ci.org/alex/rust-asn1.svg?branch=master
    :target: https://travis-ci.org/alex/rust-asn1

This is a Rust library for serializing ASN.1 structures (DER only).

Installation
------------

Add ``asn1`` to the ``[dependencies]`` section of your ``Cargo.toml``:

.. code-block:: toml

    [dependencies]
    asn1 = "*"


Usage
-----

To write a structure like::

    Signature ::= SEQUENCE {
        r INTEGER,
        s INTEGER
    }

you would write:

.. code-block:: rust

  use asn1::{Serializer}
  
  let mut s = Serializer::new(writer);
  s.write_sequence(|new_s| {
      new_s.write_int(r);
      new_s.write_int(s);
  });
