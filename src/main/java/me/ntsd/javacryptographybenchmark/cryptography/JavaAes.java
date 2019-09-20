package me.ntsd.javacryptographybenchmark.cryptography;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class JavaAes {

    private KeyGenerator ivGenerator;
    private KeyGenerator aesKeyGenerator;

    private Cipher encryptCipherAes;
    private Cipher decryptCipherAes;

    public JavaAes() throws NoSuchAlgorithmException, NoSuchPaddingException {
        aesKeyGenerator = KeyGenerator.getInstance("AES/CBC/PKCS5PADDING");
        aesKeyGenerator.init(128);  // AES 128 bit

        ivGenerator = KeyGenerator.getInstance("AES/CBC/PKCS5PADDING");
        ivGenerator.init(128); // iv is 128 bits

        encryptCipherAes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        decryptCipherAes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    }

    public byte[] encrypt(byte[] data, byte[] key, byte[] initVector) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        encryptCipherAes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(initVector));
        return encryptCipherAes.doFinal(data);
    }

    public byte[] decrypt(byte[] encryptedData, byte[] key, byte[] initVector) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        decryptCipherAes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(initVector));
        return decryptCipherAes.doFinal(encryptedData);
    }

    public KeyGenerator getIvGenerator() {
        return ivGenerator;
    }

    public KeyGenerator getAesKeyGenerator() {
        return aesKeyGenerator;
    }
}
