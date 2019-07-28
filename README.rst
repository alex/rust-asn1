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
    asn1 = "0.3"


Usage
-----

To parse a structure like::

    Signature ::= SEQUENCE {
        r INTEGER,
        s INTEGER
    }

you would write:

.. code-block:: rust

    let result = asn1::parse(data, |d| {
        return d.parse::<asn1::Sequence>()?.parse(|d| {
            let r = d.parse::<IntegerType>()?;
            let s = d.parse::<IntegerType>()?;
            return Ok((r, s));
        })
    });

    match result {
        Ok((r, s)) => println("r={}, s={}", r, s),
        Err(e) => println!("Error! {:?}", e),
    }
