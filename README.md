# CHACHA20 Showcase

Die Implementierung zeigt, wie man ChaCha20 in Verbindung mit Poly1305 nutzt.
Hierbei wird nur das JDK 17 und keine weiteren Libraries benutzt.

Dabei wird auch die Verarbeitung von Streams gezeigt, da die meisten Beispiele immer nur
auf in-Memory byte-Arrays abzielen.

Warum habe ich es ausprobiert?
In diesem Fall wegen Fefe. http://blog.fefe.de/?ts=9c135c0b

Üblicherweise verwendet man AES, bei hybriden Verfahren (RSA + AES). Das ist grundsätzlich
auch nicht verkehrt, da man dann auf Verfahren setzt die erprobt sind.
Allerdings gibt es bei AES berechtigte Kritikpunkte, die u.a mit den Betriebsmodi zusammenhängen (ECB z.b). Soweit ich weiß.
Bei AES gibt es zudem viele Möglichkeiten, bei denen in der Entwicklung Fehler gemacht werden können die
dann die Crypto schwächen. Das ist wohl bei ChaCha20 weniger das Problem.

siehe auch: https://www.reddit.com/r/crypto/comments/f7c2nv/chacha20_v_aes256/

## Links
https://mkyong.com/java/java-11-chacha20-poly1305-encryption-examples/

https://en.wikipedia.org/wiki/ChaCha20-Poly1305

https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html

https://soatok.blog/2022/02/09/using-rsa-securely-in-2022/

https://soatok.blog/2020/05/13/why-aes-gcm-sucks/