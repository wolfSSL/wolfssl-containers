/* CryptoTestSuite.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * JCA tests for the wolfSSL FIPS container. Each service must come from
 * wolfJCE, and the algorithms java.security disables must be disabled.
 */
public class CryptoTestSuite {

    private static final String TEST_DATA =
        "This is test data for FIPS cryptographic operations";
    private static final String PROVIDER_WOLFJCE = "wolfJCE";

    /* SHA1withRSA is approved for verification only, so the test verifies
     * this fixed signature over TEST_DATA with this public key (X.509,
     * Base64). */
    private static final String SHA1_RSA_PUBKEY =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8dqstBl0/s4E5g96pPw5" +
        "M7jjSxuNqsXOwYQv3ugFHgcLOkkmZehYfSd9EKvF7W2ZdB+WVvFBzVxD687K0KuJ" +
        "C37XV8neyyMzHmOnN+lAeHHNuEPKVBQ5+vNB7NWxUzApZ+Rkei7VcOrXaQa2e0m3" +
        "RQlUV9Sgffue2+Znyx4kLRfJsxjJprzK7aZRLYYvaNMA7QbLaQvXkD0CDxKIzf3+" +
        "kzwptYNWiPcBGx6C91GaHk6bM/lNoRBqM/gC4gh5q9tD4awfkStMF/kTppNArgvA" +
        "FEyP038Lpo6N6XxCefytsNDRxvrk6KOY2qeA33zc7k0lii1Cug0PlY4zrQ8fBr/6" +
        "VQIDAQAB";
    private static final String SHA1_RSA_SIG =
        "4MRxjqVz78r6FDZ9fJYGPXEmwAgzBTzmMHVlNO/3EJSlwuzICqyRD22vdX2NqdHH" +
        "YuaRojM8TJNr2sEoQY/3nOKfyorSP95rqIhuBO9Nt3irzPPerAhMJDPV4qrM4/lp" +
        "L/bIkKBd4vmGUaIBkxBplTtUS0NoekwlJJTO/UYvtm/Wocxyn4I9p0NluyjcNZdD" +
        "qtQyuY3M0p4yHG/E2/G2SRO3YVN26AkJTpbNE4kRnskcNyWDtYRaPN2bI5OK/KY4" +
        "ELhraWvg9DW3Rb+Si9nM+oJib1APL9XYZkJnAY309JwAIp4leFZQ+qsXi+p/GsaL" +
        "HRTyatJbXHuzVFWq0+CCvQ==";

    public static void main(String[] args) {
        CryptoTestSuite suite = new CryptoTestSuite();
        suite.runAllTests();
    }

    public void runAllTests() {
        System.out.println(
            "=== wolfSSL FIPS JCA Cryptographic Operations Test Suite ===\n");

        try {
            verifyProviderSetup();
            testMessageDigestOperations();
            testSymmetricEncryption();
            testAsymmetricEncryption();
            testMacOperations();
            testDigitalSignatures();
            testKeyGeneration();
            testKeyAgreement();
            testAlgorithmParameterGenerators();
            testSecureRandom();

            System.out.println("\n=== All JCA Cryptographic Tests PASSED ===");

        } catch (Exception e) {
            System.err.println("\nERROR: JCA Cryptographic test failed!");
            System.err.println("Exception: " + e.getClass().getName() +
                ": " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void verifyProviderSetup()
        throws SecurityException {

        System.out.println("Verifying wolfJCE Provider Setup:");

        Provider wolfJCE = Security.getProvider(PROVIDER_WOLFJCE);
        if (wolfJCE == null) {
            throw new SecurityException("wolfJCE provider not found");
        }

        System.out.println("   wolfJCE provider found: " + wolfJCE.getName() +
            " v" + wolfJCE.getVersion());
        System.out.println("   Provider info: " + wolfJCE.getInfo());
        System.out.println();
    }

    /* Fail unless the provider is wolfJCE */
    private static void requireWolfJce(String what, Provider provider) {
        if (!PROVIDER_WOLFJCE.equals(provider.getName())) {
            throw new SecurityException(what + " not using wolfJCE " +
                "provider: " + provider.getName());
        }
    }

    private void testMessageDigestOperations()
        throws Exception {

        System.out.println("Testing Message Digest Operations:");

        String[] algorithms = {
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        };

        for (String algorithm : algorithms) {
            MessageDigest md = MessageDigest.getInstance(algorithm);

            if (!PROVIDER_WOLFJCE.equals(md.getProvider().getName())) {
                throw new SecurityException("MessageDigest " + algorithm +
                    " not using wolfJCE provider");
            }

            byte[] digest = md.digest(TEST_DATA.getBytes());
            System.out.println("   " + algorithm + ": " +
                bytesToHex(digest).substring(0, 16) + "... (wolfJCE)");
        }
        System.out.println();
    }

    private void testSymmetricEncryption()
        throws Exception {

        System.out.println("Testing Symmetric Encryption (AES):");

        testAesGcm();
        testAesCbc();
        testAesEcb();
        testAesCtr();
        testAesOfb();
        testAesCcm();

        System.out.println();
    }

    private void testAesGcm()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/GCM cipher not using wolfJCE provider");
        }

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-GCM encryption/decryption failed");
        }

        System.out.println(
            "   AES-GCM 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesCbc()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/CBC cipher not using wolfJCE provider");
        }

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-CBC encryption/decryption failed");
        }

        System.out.println(
            "   AES-CBC 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesEcb()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/ECB cipher not using wolfJCE provider");
        }

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-ECB encryption/decryption failed");
        }

        System.out.println(
            "   AES-ECB 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesCtr()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/CTR cipher not using wolfJCE provider");
        }

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-CTR encryption/decryption failed");
        }

        System.out.println(
            "   AES-CTR 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesOfb()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");

        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/OFB cipher not using wolfJCE provider");
        }

        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-OFB encryption/decryption failed");
        }

        System.out.println(
            "   AES-OFB 256-bit: Encryption/Decryption successful (wolfJCE)");
    }

    private void testAesCcm()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");

        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "AES/CCM cipher not using wolfJCE provider");
        }

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        /* CCM takes a GCMParameterSpec (tag length and nonce) */
        GCMParameterSpec ccmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ccmSpec);
        byte[] encrypted = cipher.doFinal(TEST_DATA.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, key, ccmSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!TEST_DATA.equals(new String(decrypted))) {
            throw new SecurityException(
                "AES-CCM encryption/decryption failed");
        }

        System.out.println(
            "   AES-CCM 256-bit: Encryption/Decryption successful (wolfJCE)");

    }

    private void testAsymmetricEncryption()
        throws Exception {

        System.out.println("Testing Asymmetric Encryption (RSA):");

        testRsaNoPadding();

        /* Padded RSA encryption (key transport) is disabled */
        testDisabledRsaCiphers();

        System.out.println();
    }

    private void testRsaNoPadding()
        throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

        if (!PROVIDER_WOLFJCE.equals(cipher.getProvider().getName())) {
            throw new SecurityException(
                "RSA/ECB/NoPadding cipher not using wolfJCE provider");
        }

        byte[] msg = "Hello FIPS!".getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal(msg);

        /* Decryption returns the full key-size block: zeros, then the
         * message */
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);

        byte[] expected = new byte[256];
        System.arraycopy(msg, 0, expected, 256 - msg.length, msg.length);
        if (encrypted.length != 256 || !Arrays.equals(expected, decrypted)) {
            throw new SecurityException(
                "RSA/ECB/NoPadding encryption/decryption failed");
        }

        System.out.println(
            "   RSA/ECB/NoPadding 2048-bit: Encryption/Decryption " +
            "successful (wolfJCE)");
    }

    /**
     * Padded RSA encryption is key transport, which certificate #5548 does
     * not claim, so jdk.crypto.disabledAlgorithms disables it.
     */
    private void testDisabledRsaCiphers() throws NoSuchPaddingException {
        String[] transformations = {
            "RSA", "RSA/ECB/PKCS1Padding",
            "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA1AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
            "RSA/ECB/OAEPWithSHA256AndMGF1Padding"
        };

        for (String transformation : transformations) {
            try {
                Cipher.getInstance(transformation);
                throw new SecurityException(transformation +
                    " should be disabled by jdk.crypto.disabledAlgorithms");
            } catch (NoSuchAlgorithmException e) {
                checkDisabledMessage(transformation, e);
                System.out.println("   " + transformation +
                    ": disabled (jdk.crypto.disabledAlgorithms)");
            }
        }
    }

    private void testMacOperations()
        throws Exception {

        System.out.println("Testing MAC Operations:");

        String[] algorithms = {
            "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512",
            "AESCMAC", "AES-CMAC", "AESGMAC", "AES-GMAC"
        };

        for (String algorithm : algorithms) {
            KeyGenerator keyGen;
            if (algorithm.equals("AESCMAC") ||
                algorithm.equals("AES-CMAC") ||
                algorithm.equals("AESGMAC") ||
                algorithm.equals("AES-GMAC")) {

                keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
            } else {
                keyGen = KeyGenerator.getInstance(algorithm);
            }

            SecretKey key = keyGen.generateKey();
            Mac mac = Mac.getInstance(algorithm);

            if (!PROVIDER_WOLFJCE.equals(mac.getProvider().getName())) {
                throw new SecurityException("MAC " + algorithm +
                    " not using wolfJCE provider");
            }

            /* AES-GMAC needs a GCMParameterSpec with an IV */
            if (algorithm.equals("AESGMAC") ||
                algorithm.equals("AES-GMAC")) {

                SecureRandom random = new SecureRandom();
                byte[] iv = new byte[12];
                random.nextBytes(iv);
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                mac.init(key, gcmSpec);
            } else {
                mac.init(key);
            }
            byte[] macValue = mac.doFinal(TEST_DATA.getBytes());

            System.out.println("   " + algorithm + ": " +
                bytesToHex(macValue).substring(0, 16) + "... (wolfJCE)");

        }
        System.out.println();
    }

    private void testDigitalSignatures()
        throws Exception {

        System.out.println("Testing Digital Signatures:");

        testRsaSignatures();
        testEcdsaSignatures();
        testRsaPssSignatures();
        testDisabledSignatures();

        System.out.println();
    }

    private void testRsaSignatures()
        throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String[] algorithms = {
            "SHA224withRSA", "SHA256withRSA", "SHA384withRSA",
            "SHA512withRSA"
        };

        verifySha1Signature("SHA1withRSA", "RSA", SHA1_RSA_PUBKEY,
            SHA1_RSA_SIG);

        for (String algorithm : algorithms) {
            Signature signature = Signature.getInstance(algorithm);

            if (!PROVIDER_WOLFJCE.equals(signature.getProvider().getName())) {
                throw new SecurityException(
                    "Signature " + algorithm + " not using wolfJCE provider");
            }

            signature.initSign(keyPair.getPrivate());
            signature.update(TEST_DATA.getBytes());
            byte[] signatureBytes = signature.sign();

            signature.initVerify(keyPair.getPublic());
            signature.update(TEST_DATA.getBytes());
            boolean verified = signature.verify(signatureBytes);

            if (!verified) {
                throw new SecurityException(
                    "Signature verification failed for " + algorithm);
            }

            System.out.println("   " + algorithm +
                ": Sign/Verify successful (wolfJCE)");
        }
    }

    private void testEcdsaSignatures() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGen.initialize(ecSpec);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String[] algorithms = {
            "SHA224withECDSA", "SHA256withECDSA",
            "SHA384withECDSA", "SHA512withECDSA", "SHA3-224withECDSA",
            "SHA3-256withECDSA", "SHA3-384withECDSA", "SHA3-512withECDSA"
        };

        for (String algorithm : algorithms) {
            Signature signature = Signature.getInstance(algorithm);

            if (!PROVIDER_WOLFJCE.equals(signature.getProvider().getName())) {
                throw new SecurityException("Signature " + algorithm +
                    " not using wolfJCE provider");
            }

            signature.initSign(keyPair.getPrivate());
            signature.update(TEST_DATA.getBytes());
            byte[] signatureBytes = signature.sign();

            signature.initVerify(keyPair.getPublic());
            signature.update(TEST_DATA.getBytes());
            boolean verified = signature.verify(signatureBytes);

            if (!verified) {
                throw new SecurityException(
                    "Signature verification failed for " + algorithm);
            }

            System.out.println("   " + algorithm +
                ": Sign/Verify successful (wolfJCE)");
        }
    }

    /**
     * Verify a fixed SHA-1 signature over TEST_DATA, and confirm it does not
     * verify over modified data.
     */
    private void verifySha1Signature(String algorithm, String keyAlg,
        String pubKey, String sig) throws Exception {

        PublicKey key = KeyFactory.getInstance(keyAlg).generatePublic(
            new X509EncodedKeySpec(Base64.getDecoder().decode(pubKey)));
        byte[] sigBytes = Base64.getDecoder().decode(sig);
        Signature signature = Signature.getInstance(algorithm);

        if (!PROVIDER_WOLFJCE.equals(signature.getProvider().getName())) {
            throw new SecurityException("Signature " + algorithm +
                " not using wolfJCE provider");
        }

        signature.initVerify(key);
        signature.update(TEST_DATA.getBytes());
        if (!signature.verify(sigBytes)) {
            throw new SecurityException(
                "Signature verification failed for " + algorithm);
        }

        signature.initVerify(key);
        signature.update((TEST_DATA + "!").getBytes());
        if (signature.verify(sigBytes)) {
            throw new SecurityException(
                algorithm + " signature verified over modified data");
        }

        System.out.println("   " + algorithm +
            ": Verify successful (wolfJCE, verify only)");
    }

    /**
     * Check the signatures that jdk.crypto.disabledAlgorithms disables,
     * because certificate #5548 does not approve them.
     */
    private void testDisabledSignatures() {
        String[] algorithms = {
            "SHA1withECDSA", "SHA3-224withRSA", "SHA3-256withRSA",
            "SHA3-384withRSA", "SHA3-512withRSA"
        };

        for (String algorithm : algorithms) {
            try {
                Signature.getInstance(algorithm);
                throw new SecurityException(algorithm +
                    " should be disabled by jdk.crypto.disabledAlgorithms");
            } catch (NoSuchAlgorithmException e) {
                checkDisabledMessage(algorithm, e);
                System.out.println("   " + algorithm +
                    ": disabled (jdk.crypto.disabledAlgorithms)");
            }
        }
    }

    /**
     * Fail unless jdk.crypto.disabledAlgorithms caused the exception ("... is
     * disabled"), not a missing or renamed service.
     */
    private static void checkDisabledMessage(String name,
        NoSuchAlgorithmException e) {

        if (e.getMessage() == null || !e.getMessage().endsWith("is disabled")) {
            throw new SecurityException(name + ": expected a " +
                "jdk.crypto.disabledAlgorithms block, got: " + e);
        }
    }

    private void testRsaPssSignatures()
        throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String[] algorithms = {
            "RSASSA-PSS", "SHA224withRSA/PSS", "SHA256withRSA/PSS",
            "SHA384withRSA/PSS", "SHA512withRSA/PSS"
        };

        for (String algorithm : algorithms) {
            Signature signature = Signature.getInstance(algorithm);

            if (!PROVIDER_WOLFJCE.equals(
                    signature.getProvider().getName())) {
                throw new SecurityException(
                    "Signature " + algorithm + " not using wolfJCE provider");
            }

            /* RSASSA-PSS needs explicit parameters */
            if (algorithm.equals("RSASSA-PSS")) {
                PSSParameterSpec pssSpec = new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
                signature.setParameter(pssSpec);
            }

            signature.initSign(keyPair.getPrivate());
            signature.update(TEST_DATA.getBytes());
            byte[] signatureBytes = signature.sign();

            /* Set the PSS parameters again for verification */
            signature.initVerify(keyPair.getPublic());
            if (algorithm.equals("RSASSA-PSS")) {
                PSSParameterSpec pssSpec = new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
                signature.setParameter(pssSpec);
            }
            signature.update(TEST_DATA.getBytes());
            boolean verified = signature.verify(signatureBytes);

            if (!verified) {
                throw new SecurityException(
                    "Signature verification failed for " + algorithm);
            }

            System.out.println("   " + algorithm +
                ": Sign/Verify successful (wolfJCE)");
        }
    }

    private void testKeyGeneration()
        throws Exception {

        System.out.println("Testing Key Generation:");

        testSymmetricKeyGeneration();
        testAsymmetricKeyGeneration();

        System.out.println();
    }

    private void testSymmetricKeyGeneration()
        throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        requireWolfJce("KeyGenerator AES", keyGen.getProvider());

        int[] keySizes = {128, 192, 256};
        for (int keySize : keySizes) {
            keyGen.init(keySize);
            SecretKey key = keyGen.generateKey();

            if (key.getEncoded().length != keySize / 8) {
                throw new SecurityException(
                    "Generated AES key has wrong size");
            }

            System.out.println("   AES-" + keySize +
                " key generated successfully");
        }
    }

    private void testAsymmetricKeyGeneration()
        throws Exception {

        testRsaKeyGeneration();
        testEcKeyGeneration();
    }

    private void testRsaKeyGeneration()
        throws Exception {

        int[] keySizes = {2048, 3072, 4096};

        for (int keySize : keySizes) {
            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
            requireWolfJce("KeyPairGenerator RSA", rsaKeyGen.getProvider());
            rsaKeyGen.initialize(keySize);
            KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
            System.out.println("   RSA-" + keySize +
                " key pair generated successfully");
        }
    }

    private void testEcKeyGeneration()
        throws Exception {

        String[] curves = {
            "secp256r1",                /* P-256 */
            "secp384r1",                /* P-384 */
            "secp521r1"                 /* P-521 */
        };

        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        requireWolfJce("KeyPairGenerator EC", ecKeyGen.getProvider());

        for (String curveName : curves) {
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            ecKeyGen.initialize(ecSpec);
            KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
            System.out.println("   EC-" + curveName +
                " key pair generated successfully");
        }
    }

    private void testKeyAgreement()
        throws Exception {

        System.out.println("Testing Key Agreement Protocols:");

        testEcdhKeyAgreement();

        System.out.println();
    }

    private void testEcdhKeyAgreement()
        throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");

        ECGenParameterSpec ecSpec;
        ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGen.initialize(ecSpec);

        KeyPair keyPairA = keyPairGen.generateKeyPair();
        KeyPair keyPairB = keyPairGen.generateKeyPair();

        /* Side A */
        KeyAgreement keyAgreementA = KeyAgreement.getInstance("ECDH");

        if (!PROVIDER_WOLFJCE.equals(keyAgreementA.getProvider().getName())) {
            throw new SecurityException(
                "KeyAgreement ECDH not using wolfJCE provider");
        }

        keyAgreementA.init(keyPairA.getPrivate());
        keyAgreementA.doPhase(keyPairB.getPublic(), true);
        byte[] sharedSecretA = keyAgreementA.generateSecret();

        /* Side B */
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("ECDH");
        keyAgreementB.init(keyPairB.getPrivate());
        keyAgreementB.doPhase(keyPairA.getPublic(), true);
        byte[] sharedSecretB = keyAgreementB.generateSecret();

        if (!java.util.Arrays.equals(sharedSecretA, sharedSecretB)) {
            throw new SecurityException("ECDH shared secrets do not match");
        }

        System.out.println("   ECDH Key Agreement: Shared secret computed " +
            "successfully (wolfJCE)");
        System.out.println("   Shared secret length: " +
            sharedSecretA.length + " bytes");
        System.out.println("   Shared secret sample: " +
            bytesToHex(sharedSecretA).substring(0, 16) + "...");
    }

    private void testAlgorithmParameterGenerators()
        throws Exception {

        System.out.println("Testing Algorithm Parameter Generators:");

        /* TODO: enable when wolfJCE implements the DH
         * AlgorithmParameterGenerator */
        //testDhParameterGeneration();

        System.out.println(
            "   DH Parameter Generation: Not implemented in wolfJCE");
        System.out.println();
    }

    private void testDhParameterGeneration()
        throws Exception {

        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");

        if (!PROVIDER_WOLFJCE.equals(paramGen.getProvider().getName())) {
            throw new SecurityException(
                "DH AlgorithmParameterGenerator not using wolfJCE provider");
        }

        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();

        System.out.println("   DH Parameter Generation: 1024-bit parameters " +
            "generated (wolfJCE)");
        System.out.println("   Algorithm: " + params.getAlgorithm());

    }

    private void testSecureRandom()
        throws Exception {

        System.out.println("Testing Secure Random:");

        testDefaultSecureRandom();
        testSpecificSecureRandomAlgorithms();

        System.out.println();
    }

    private void testDefaultSecureRandom()
        throws Exception {

        SecureRandom random = new SecureRandom();

        String algorithm = random.getAlgorithm();
        String providerName = random.getProvider().getName();
        System.out.println("   Default SecureRandom algorithm: " +
            algorithm + " (" + providerName + ")");
        requireWolfJce("Default SecureRandom", random.getProvider());

        testRandomnessQuality(random, "Default SecureRandom");
    }

    private void testSpecificSecureRandomAlgorithms()
        throws Exception {

        String[] algorithms = {
            "DEFAULT", "HashDRBG"
        };

        for (String algorithm : algorithms) {
            SecureRandom random = SecureRandom.getInstance(algorithm);
            String providerName = random.getProvider().getName();
            System.out.println("   " + algorithm +
                " available from: " + providerName);
            requireWolfJce("SecureRandom " + algorithm, random.getProvider());

            byte[] testBytes = new byte[16];
            random.nextBytes(testBytes);
            System.out.println("     Generated entropy: " +
                bytesToHex(testBytes));
        }
    }

    private void testRandomnessQuality(SecureRandom random, String name)
        throws Exception {

        byte[][] samples = new byte[5][32];
        for (int i = 0; i < 5; i++) {
            random.nextBytes(samples[i]);
        }

        /* Verify no duplicate samples */
        for (int i = 0; i < samples.length; i++) {
            for (int j = i + 1; j < samples.length; j++) {
                if (java.util.Arrays.equals(samples[i], samples[j])) {
                    throw new SecurityException(
                        "SecureRandom generated duplicate samples");
                }
            }
        }

        /* Check for non-zero bytes */
        boolean hasNonZero = false;
        for (byte[] sample : samples) {
            for (byte b : sample) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            if (hasNonZero) break;
        }

        if (!hasNonZero) {
            throw new SecurityException("SecureRandom generated all zeros");
        }

        /* Test different generation methods */
        int randomInt = random.nextInt();
        long randomLong = random.nextLong();
        double randomDouble = random.nextDouble();

        System.out.println("   " + name + ": Quality checks passed");
        System.out.println("   Generated 5 unique 256-bit samples");
        System.out.println("   Sample entropy methods: int=" + randomInt +
            ", long=" + randomLong + ", double=" +
            String.format("%.6f", randomDouble));
        System.out.println("   Sample bytes: " +
            bytesToHex(samples[0]).substring(0, 32) + "...");
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}

