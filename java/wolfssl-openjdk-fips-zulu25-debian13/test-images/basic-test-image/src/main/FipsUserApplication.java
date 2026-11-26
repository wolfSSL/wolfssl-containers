/* FipsUserApplication.java
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
import java.net.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;

/**
 * Runs the JCA and TLS test suites and a few example use cases on the
 * wolfSSL FIPS Java container.
 */
public class FipsUserApplication {

    public static void main(String[] args) {
        enableDebugFromEnvironment();

        System.out.println("=== wolfSSL Simple Java FIPS Test Application ===");
        System.out.println("Demonstrating FIPS 140-3 validated operations\n");

        FipsUserApplication app = new FipsUserApplication();

        try {
            app.runProviderVerification();
            app.runCryptographicTests();
            app.runTlsTests();
            app.runRealWorldScenarios();

            System.out.println("\n=== FIPS Tests COMPLETED SUCCESSFULLY ===");

        } catch (Exception e) {
            System.err.println("\nERROR: FIPS application test failed!");
            System.err.println("Exception: " + e.getClass().getName() +
                ": " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void enableDebugFromEnvironment() {
        System.out.println("Debug configuration:");
        System.out.println("  WOLFJCE_DEBUG env var: " +
            System.getenv("WOLFJCE_DEBUG"));
        System.out.println("  WOLFJSSE_DEBUG env var: " +
            System.getenv("WOLFJSSE_DEBUG"));

        /* Set the debug properties from the environment variables */
        if ("true".equals(System.getenv("WOLFJCE_DEBUG"))) {
            System.setProperty("wolfjce.debug", "true");
            System.out.println(
                "  Enabled wolfjce.debug from environment variable");
        }
        if ("true".equals(System.getenv("WOLFJSSE_DEBUG"))) {
            System.setProperty("wolfjsse.debug", "true");
            System.out.println(
                "  Enabled wolfjsse.debug from environment variable");
        }

        System.out.println("  wolfjce.debug system property: " +
            System.getProperty("wolfjce.debug"));
        System.out.println("  wolfjsse.debug system property: " +
            System.getProperty("wolfjsse.debug"));
        System.out.println();
    }

    private void runProviderVerification()
        throws Exception {

        System.out.println("=== Provider Verification ===");

        Provider[] providers = Security.getProviders();
        System.out.println("Currently loaded security providers:");
        for (int i = 0; i < providers.length; i++) {
            Provider p = providers[i];
            System.out.println("  " + (i + 1) + ". " + p.getName() + " v" +
                p.getVersion() + " - " + p.getInfo());
        }

        if (!"wolfJCE".equals(providers[0].getName())) {
            throw new SecurityException("wolfJCE not at position 1");
        }
        if (!"wolfJSSE".equals(providers[1].getName())) {
            throw new SecurityException("wolfJSSE not at position 2");
        }

        System.out.println("+ wolfJCE verified at position 1");
        System.out.println("+ wolfJSSE verified at position 2");
        System.out.println();
    }

    private void runCryptographicTests()
        throws Exception {

        System.out.println("=== Cryptographic Operations Test ===");

        CryptoTestSuite cryptoSuite = new CryptoTestSuite();
        cryptoSuite.runAllTests();
    }

    private void runTlsTests()
        throws Exception {

        System.out.println("=== SSL/TLS Operations Test ===");

        TlsTestSuite tlsSuite = new TlsTestSuite();
        tlsSuite.runAllTests();
    }

    private void runRealWorldScenarios()
        throws Exception {

        System.out.println("=== Real-World Usage Scenarios ===");

        demonstrateFileEncryption();
        demonstrateDataSigning();
        demonstratePasswordHashing();
        demonstrateHttpsClient();

        System.out.println();
    }

    private void demonstrateFileEncryption()
        throws Exception {

        System.out.println("File Encryption/Decryption Scenario:");

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        String originalContent = "This is sensitive data that must be " +
            "protected with FIPS-validated encryption.";
        byte[] plaintext = originalContent.getBytes();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encrypted = cipher.doFinal(plaintext);

        System.out.println("   File encrypted using AES-256-GCM");
        System.out.println("   Original size: " + plaintext.length + " bytes");
        System.out.println("   Encrypted size: " + encrypted.length + " bytes");

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        if (!originalContent.equals(new String(decrypted))) {
            throw new SecurityException("File decryption failed");
        }

        System.out.println("   File decrypted successfully - content verified");
        System.out.println();
    }

    private void demonstrateDataSigning()
        throws Exception {

        System.out.println("Data Signing Scenario:");

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String data = "IMPORTANT CONTENT: This data is digitally " +
            "signed with FIPS-validated algorithms.";

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] digitalSignature = signature.sign();

        System.out.println("   Data signed using RSA-2048 with SHA-256");
        System.out.println("   Signature size: " + digitalSignature.length +
            " bytes");

        signature.initVerify(keyPair.getPublic());
        signature.update(data.getBytes());
        boolean verified = signature.verify(digitalSignature);

        if (!verified) {
            throw new SecurityException("Data signature verification failed");
        }

        System.out.println("   Data signature verified successfully");
        System.out.println();
    }

    private void demonstratePasswordHashing()
        throws Exception {

        System.out.println("Secure Password Hashing Scenario:");

        String password = "SecureP@ssw0rd123!";
        String salt = "RandomSalt12345";

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt.getBytes());
        byte[] hashedPassword = digest.digest(password.getBytes());

        System.out.println("   Password hashed using SHA-256");
        System.out.println("   Hash: " + bytesToHex(hashedPassword));

        digest.reset();
        digest.update(salt.getBytes());
        byte[] verificationHash = digest.digest(password.getBytes());

        if (!Arrays.equals(hashedPassword, verificationHash)) {
            throw new SecurityException("Password hash verification failed");
        }

        System.out.println("   Password verification successful");
        System.out.println();
    }

    private void demonstrateHttpsClient()
        throws Exception {

        System.out.println("HTTPS Client Implementation Scenario:");

        try {
            /* With null key and trust managers, wolfJSSE uses the system
             * CA certificates */
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);

            URL url = new URL("https://httpbin.org/get");
            HttpsURLConnection connection =
                (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(context.getSocketFactory());
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);

            int responseCode = connection.getResponseCode();
            System.out.println("   HTTPS connection established");
            System.out.println("   Response code: " + responseCode);

            if (responseCode == 200) {
                BufferedReader reader =
                    new BufferedReader(
                        new InputStreamReader(connection.getInputStream()));
                String line;
                StringBuilder response = new StringBuilder();
                int lineCount = 0;
                while ((line = reader.readLine()) != null && lineCount < 5) {
                    response.append(line).append("\n");
                    lineCount++;
                }
                reader.close();

                System.out.println("   Response received (first few lines):");
                System.out.println("     " + response.toString()
                    .substring(0, Math.min(100, response.length())) + "...");
            }

            connection.disconnect();
            System.out.println("   HTTPS connection closed successfully");

        } catch (Exception e) {
            System.out.println("   - HTTPS test failed: " + e.getMessage());
            throw new Exception("HTTPS test failed: " + e.getMessage(), e);
        }

        System.out.println("   wolfJSSE HTTPS client test completed");

        System.out.println();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}

