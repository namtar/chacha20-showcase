package de.catcode.crypto.chacha20;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

class ChaCha20CryptorTest {

    @Test
    void testEncryptDecrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        final String plainText = "Some Random Plaintext for encryption.";

        final Chacha20Cryptor cryptor = new Chacha20Cryptor();

        final SecretKey secretKey = cryptor.createRandomSecretKey();

        final String chiffre = cryptor.encrypt(plainText, secretKey);

        Assertions.assertNotEquals(plainText, chiffre);
        System.out.printf(chiffre);

        final String decrypted = cryptor.decrypt(chiffre, secretKey);

        Assertions.assertEquals(plainText, decrypted);
    }

    @Test
    void testEncryptDecryptStream() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {

        final String plainText = "Some Random Plaintext for encryption.";

        final Chacha20Cryptor cryptor = new Chacha20Cryptor();

        final SecretKey secretKey = cryptor.createRandomSecretKey();

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();

        cryptor.encrypt(new ByteArrayInputStream(plainText.getBytes(StandardCharsets.UTF_8)), bos, secretKey);

        Assertions.assertNotEquals(plainText, bos.toString());
        System.out.printf(HexFormat.of().formatHex(bos.toByteArray()));

        final ByteArrayOutputStream decBos = new ByteArrayOutputStream();

        cryptor.decrypt(new ByteArrayInputStream(bos.toByteArray()), decBos, secretKey);

        Assertions.assertEquals(plainText, decBos.toString());
    }
}
