package de.catcode.crypto.chacha20;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

public class Chacha20Cryptor {

    private final static String ALGORITHM = "ChaCha20-Poly1305";

    public String encrypt(final String plainText, final SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        final byte[] nonce = generateNonce(12);
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] chiffre = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        // laut https://datatracker.ietf.org/doc/html/rfc8439 ist die nonce 96 bit (12 bytes)

        // Es macht die Welt der Streamverarbeitung einfacher, wenn alles was unverschlüsselt ist prepended wird.
        final byte[] output = ByteBuffer.allocate(chiffre.length + nonce.length)
                .put(nonce)
                .put(chiffre)
                .array();

        return HexFormat.of().formatHex(output);
    }

    public void encrypt(final InputStream inputStream, final OutputStream outputStream, final SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, InvalidKeyException {

        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        final byte[] nonce = generateNonce(12);
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        try (final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
            outputStream.write(ivParameterSpec.getIV());
            inputStream.transferTo(cipherOutputStream);
        }
    }

    public String decrypt(final String chiffre, final SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        final byte[] chiffeBytes = HexFormat.of().parseHex(chiffre);
        final ByteBuffer byteBuffer = ByteBuffer.wrap(chiffeBytes);

        final byte[] encryptedText = new byte[chiffeBytes.length - 12];
        final byte[] nonce = new byte[12];
        byteBuffer.get(nonce);
        byteBuffer.get(encryptedText);

        final IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] plainTextBytes = cipher.doFinal(encryptedText);

        return new String(plainTextBytes);
    }

    public void decrypt(final InputStream inputStream, final OutputStream outputStream, final SecretKey secretKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        final byte[] nonce = new byte[12];

        inputStream.read(nonce);

        final IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

        final Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        try (final CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) {
            cipherInputStream.transferTo(outputStream);
        }
    }

    public SecretKey createRandomSecretKey() throws NoSuchAlgorithmException {
        // Dass es einen KeyGenerator Algorithmus für ChaCha20 gibt ist in https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html
        // unter KeyGenerator Algorithms aufgeführt
        final KeyGenerator keyGenerator = KeyGenerator.getInstance("ChaCha20");
        keyGenerator.init(256, SecureRandom.getInstanceStrong());
        return keyGenerator.generateKey();
    }

    public byte[] generateNonce(final int byteLength) {
        // man könnt den SecureRandom mit SHA1PRNG explizit erzeugen, jedoch ist das sowieso einer der Defaults.
        // SecureRandom.getInstance("SHA1PRNG")
        final byte[] nonce = new byte[byteLength];
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce);
        return nonce;
    }
}
