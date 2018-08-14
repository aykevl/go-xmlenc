# XML Encryption

This is a very bare-bones implementation of
[XML Encryption](https://www.w3.org/TR/xmlenc-core1/), just enough to decrypt
the SAML attributes of the [iDIN protocol](https://www.idin.nl/) provided by
(mostly) Dutch banks.

Some warnings:

  * This is unfinished. It supports almost nothing except for one specific
    combination of RSA-OAEP, SHA1, and AES-256-CBC.
  * **Do not use unauthenticated XML encryption**. It is [broken by
    design](https://crypto.stackexchange.com/q/1042/8860) and allows for a
    [padding oracle attack](https://blog.cryptographyengineering.com/2011/10/23/attack-of-week-xml-encryption/).
    Make sure the messages you're trying to decrypt have been verified in some
    way (e.g. using an [XML signature](https://www.w3.org/TR/xmldsig-core2/)).
  * This library hasn't been reviewed by a cryptographer so it may contain
    mistakes. However, as it is only decrypting stuff (which should be already
    authenticated), there is not a whole lot that can go wrong.
