package me.ntsd.javacryptographybenchmark.cryptography;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class JavaAes {

    private KeyGenerator aesKeyGenerator;

    private Cipher encryptCipherAes;
    private Cipher decryptCipherAes;

    public JavaAes() throws NoSuchAlgorithmException, NoSuchPaddingException {
        aesKeyGenerator = KeyGenerator.getInstance("AES");
        aesKeyGenerator.init(128);  // AES 128 bit

        encryptCipherAes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        decryptCipherAes = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public byte[] encrypt(byte[] data, byte[] key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        encryptCipherAes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return encryptCipherAes.doFinal(data);
    }

    public byte[] decrypt(byte[] encryptedData, byte[] key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        decryptCipherAes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        return decryptCipherAes.doFinal(encryptedData);
    }

    public KeyGenerator getAesKeyGenerator() {
        return aesKeyGenerator;
    }
}
