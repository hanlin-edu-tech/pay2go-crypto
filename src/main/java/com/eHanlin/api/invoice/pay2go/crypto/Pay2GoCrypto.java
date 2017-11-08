package com.eHanlin.api.invoice.pay2go.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * 智付X系列 API 資料加解密工具
 */
public class Pay2GoCrypto {

    private static final String SHA_256 = "SHA-256";

    private static final String CIPHER_ENCRYPT_ALGORITHM = "AES/CBC/PKCS5Padding";

    private static final String CIPHER_DECRYPT_ALGORITHM = "AES/CBC/NoPadding";

    private static final String AES = "AES";

    private static final String UTF8 = "UTF-8";

    private SecretKey hashKey;

    private AlgorithmParameterSpec hashIV;

    public Pay2GoCrypto(String hashKey, String hashIV) {
        this.hashKey = new SecretKeySpec(toUtf8Bytes(hashKey), AES);
        this.hashIV = new IvParameterSpec(toUtf8Bytes(hashIV));
    }

    @SuppressWarnings("unused")
    public String sha256(String text) {
        MessageDigest messageDigest;

        try {
            messageDigest = MessageDigest.getInstance(SHA_256);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }

        messageDigest.update(text.getBytes());
        return byteArrayToHexString(messageDigest.digest());
    }

    @SuppressWarnings("unused")
    public String encrypt(String text) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ENCRYPT_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, hashKey, hashIV);
            return byteArrayToHexString(cipher.doFinal(toUtf8Bytes(text)));

        } catch (Exception e) {
            throw new RuntimeException("data encrypting error: " + e.getMessage());
        }
    }

    @SuppressWarnings("unused")
    public String decrypt(String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_DECRYPT_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, hashKey, hashIV);
            byte[] decryptedBytes = cipher.doFinal(hexStringToByteArray(encryptedText));
            int paddingLength = decryptedBytes[decryptedBytes.length - 1];
            int dataLength = decryptedBytes.length - paddingLength;
            return new String(Arrays.copyOf(decryptedBytes, dataLength), UTF8);

        } catch (Exception e) {
            throw new RuntimeException("data decrypting error: " + e.getMessage());
        }
    }

    /**
     * 位元組陣列轉16進位字串
     * @param bytes
     */
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }

        return builder.toString();
    }

    /**
     * 16進位字串轉位元組陣列
     * @param hex
     */
    public static byte[] hexStringToByteArray(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int begin = i * 2;
            bytes[i] = (byte) Integer.parseInt(hex.substring(begin, begin + 2), 16);
        }

        return bytes;
    }

    /**
     * 字串轉 utf-8 位元組陣列
     * @param text
     */
    public static byte[] toUtf8Bytes(String text) {
        try {
            return text.getBytes(UTF8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 fucking unsupported.");
        }
    }

}

