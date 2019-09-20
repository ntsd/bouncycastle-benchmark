package me.ntsd.bouncycastlebenchmark.encryption;

import me.ntsd.bouncycastlebenchmark.benchmark.BenchmarkAlgorithm;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Security;


public class BouncyCastleAesBenchmark implements BenchmarkAlgorithm {

    private byte[] password;
    private KeyGenerator ivGen;

    public BouncyCastleAesBenchmark() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); //key is 256 bits
        password = keyGen.generateKey().getEncoded();

        ivGen = KeyGenerator.getInstance("AES");
        ivGen.init(128); //iv is 128 bits
    }

    private static byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
        byte[] outputBuffer = new byte[cipher.getOutputSize(data.length)];

        int length1 = cipher.processBytes(data,  0, data.length, outputBuffer, 0);
        int length2 = cipher.doFinal(outputBuffer, length1);

        byte[] result = new byte[length1 + length2];

        System.arraycopy(outputBuffer, 0, result, 0, result.length);

        return result;
    }

    private static byte[] encrypt(byte[] plain, CipherParameters ivAndKey) throws Exception {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(
                        new AESEngine()
                )
        );

        aes.init(true, ivAndKey);

        return cipherData(aes, plain);

    }

    private static byte[] decrypt(byte[] cipher, CipherParameters ivAndKey) throws Exception {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(
                        new AESEngine()
                )
        );
        aes.init(false,  ivAndKey);

        return cipherData(aes, cipher);
    }

    @Override
    public void run(String text) throws Exception {
        byte[] iv = ivGen.generateKey().getEncoded();

        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(password), iv);

        byte[] plainText = text.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessage = encrypt(plainText, ivAndKey);

        CipherParameters ivAndKey2 = new ParametersWithIV(new KeyParameter(password), iv);

        String decryptedMessage = new String(decrypt(encryptedMessage, ivAndKey2));

        if (!decryptedMessage.equals(text)) {
            throw new Exception("not match");
        }
    }

    @Override
    public String getAlgorithmName() {
        return "Bouncy Castle AES";
    }
}
