elgamal-for-private-comm
========================

This is a proof of concept implementation of a private network communication protocol using ElGamal. The protocol itselft is described in the following article 

[1] Christophe Bidan, Antoine Guellier and Nicoas Prigent, "Homomorphic Cryptography-based Privacy-Preserving Network Communications", ATIS 2014

This program uses plain PHP and no library. It is solely intended to verify the arithmetics involved in the ElGamal homomorphic operations within the protocol. The code is published under license CeCILL, a French GNU GPL-like license, so as to support code-sharing and allow verification of the figures reported in the article.

WARNING: This is an academic implementation and should NOT be used or considered as secure or efficient code.

HOW TO USE
----------

Solely php is needed. Symply type:
```
php main.php
```

Parameters such as the security parameter lambda can be chosen in main.php
