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

you'd first declare it:

.. code-block:: rust

    extern crate asn1;

    asn1!(
        Signature ::= SEQUENCE {
            r INTEGER,
            s INTEGER,
        }
    );

Yes, that's right, with ``rust-asn1`` you declare an ASN.1 ``SEQUENCE`` the
same way the RFC does.

Then to serialize one:

.. code-block:: rust

    let sig = Signature{
        r: 100,
        s: 200
    };
    let data = sig.to_der();

and to read one:

.. code-block:: rust

    match Signature::from_der(data) {
        Ok(sig) => println!("r={}, s={}", sig.r, sig.s),
        Err(e) => println!("Error! {}", e),
    }
