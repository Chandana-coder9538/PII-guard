package com.piiguard.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-256-GCM. Output layout: 12-byte IV || ciphertext+tag. */
public class AesGcm {
    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public AesGcm(String passphrase) {
        try {
            byte[] k = MessageDigest.getInstance("SHA-256").digest(passphrase.getBytes(StandardCharsets.UTF_8));
            this.key = new SecretKeySpec(k, "AES");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] encrypt(String plain) {
        try {
            byte[] iv = new byte[12];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public String decrypt(byte[] blob) {
        try {
            ByteBuffer bb = ByteBuffer.wrap(blob);
            byte[] iv = new byte[12];
            bb.get(iv);
            byte[] ct = new byte[bb.remaining()];
            bb.get(ct);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            return new String(c.doFinal(ct), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }

    /** The three parts of a stored blob (JCE appends the 16-byte tag to the ciphertext). */
    public record Parts(byte[] iv, byte[] ciphertext, byte[] tag) {}

    public Parts split(byte[] blob) {
        if (blob.length < 12 + 16) throw new IllegalArgumentException("blob too short");
        return new Parts(Arrays.copyOfRange(blob, 0, 12),
            Arrays.copyOfRange(blob, 12, blob.length - 16),
            Arrays.copyOfRange(blob, blob.length - 16, blob.length));
    }

    public static byte[] join(Parts p) {
        return ByteBuffer.allocate(p.iv().length + p.ciphertext().length + p.tag().length)
            .put(p.iv()).put(p.ciphertext()).put(p.tag()).array();
    }

    /** Safe to display: first 4 bytes of SHA-256(key). Never the key itself. */
    public String keyFingerprint() {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
            return HexFormat.of().formatHex(d, 0, 4);
        } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
}