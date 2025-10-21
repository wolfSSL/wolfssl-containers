/* FipsInitCheck.java
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
import java.util.regex.*;
import java.security.*;
import javax.net.ssl.*;
import javax.crypto.*;

/**
 * FIPS POST (Power-On Self Test) verification for wolfSSL Java providers.
 * This class includes the following checks, and will terminate the container
 * if any fail.
 *     - Checks if a SecurityManager is active (informational)
 *     - Lists all currently registered security providers (informational)
 *     - Confirms wolfJCE and wolfJSSE providers are registered at
 *       priority 1 and 2 respectively
 *     - Verifies system CA certificates are in WKS format for FIPS compliance
 *     - Forces a FIPS Power-On Self Test (POST) run by initializing
 *       a MessageDigest object from wolfJCE
 *     - Performs sanity checks on the java.security configuration file
 *     - Checks availability of FIPS-approved algorithm classes
 *     - Performs a comprehensive algorithm coverage check to ensure
 *       no unexpected algorithms are available in the FIPS environment
 *
 * This class is intended to be run as a standalone Java application to verify
 * that the wolfSSL Java providers are correctly configured and operational
 * in FIPS mode.
 */
public class FipsInitCheck {

    public static void main(String[] args) {
        new FipsInitCheck().runTests();
    }

    public void runTests() {

        try {
            /* Check if Security Manager is active, informational only */
            SecurityManager sm = System.getSecurityManager();
            System.out.println("\nSecurity Manager: " +
                (sm == null ? "None" : sm.getClass().getName()));

            /* List all currently loaded providers, informational */
            listAllRegisteredSecurityProviders();

            /* Ensure wolfJCE and wolfJSSE are registered at correct priority */
            confirmWolfSSLProvidersAreRegistered();

            /* Verify system CA certs are in WKS format for FIPS compliance */
            verifyCACertificatesAreWKSFormat();

            /* Force run FIPS Power-On Self Test (POST) */
            forceRunPOST();

            /* Sanity checks on java.security provider configuration */
            javaSecuritySanityChecks();

            /* Sanity checks on availability of FIPS algorithm services */
            javaFIPSAlgorithmAvailabilityChecks();

            /* Verify all available JCA algorithms/services use
             * wolfSSL providers */
            verifyAllAlgorithmsUseWolfSSLProviders();

            /* Additional FIPS security compliance tests */
            additionalFIPSSecurityTests();

        } catch (Exception e) {
            System.err.println("\nERROR: FIPS provider verification failed!");
            System.err.println("Exception: " + e.getClass().getName() + ": " +
                e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * List all currently registered security providers in the JVM.
     */
    public void listAllRegisteredSecurityProviders() {

        Provider[] providers = Security.getProviders();

        System.out.println("\nCurrently loaded security providers:");

        for (int i = 0; i < providers.length; i++) {
            Provider p = providers[i];
            System.out.println("\t" + (i + 1) + ". " + p.getName() +
                " v" + p.getVersion() + " - " + p.getInfo());
        }
    }

    /**
     * Confirm that wolfJCE and wolfJSSE providers are registered at the
     * system level, and that wolfJCE is priority 1 and wolfJSSE is
     * prioirty 2.
     *
     * @throws SecurityException if the providers are not registered, or
     *         are in the wrong order.
     */
    public void confirmWolfSSLProvidersAreRegistered()
        throws SecurityException {

        System.out.println("\nVerifying wolfSSL providers are registered...");

        Provider[] providers = Security.getProviders();

        /* Verify wolfJCE provider is loaded */
        Provider wolfJCE = Security.getProvider("wolfJCE");
        if (wolfJCE == null) {
            throw new SecurityException("ERROR: wolfJCE provider not " +
                "loaded, check java.security configuration.");
        }

        /* Verify wolfJCE provider is at priority position 1 */
        int jcePos = java.util.Arrays.asList(providers).indexOf(wolfJCE) + 1;
        if (jcePos != 1) {
            throw new SecurityException(
                "ERROR: wolfJCE provider is not at position 1, " +
                "actual position: " + jcePos);
        }
        System.out.println("\twolfJCE provider verified at position " +
            jcePos);

        /* Verify wolfJSSE provider is loaded */
        Provider wolfJSSE = Security.getProvider("wolfJSSE");
        if (wolfJSSE == null) {
            throw new SecurityException("ERROR: wolfJSSE provider not " +
                "loaded, check java.security configuration.");
        }

        /* Verify wolfJSSE provider is at priority position 2 */

        int jssePos = java.util.Arrays.asList(providers).indexOf(wolfJSSE) + 1;
        if (jssePos != 2) {
            throw new SecurityException(
                "ERROR: wolfJSSE provider is not at position 2, " +
                "actual position: " + jssePos);
        }
        System.out.println("\twolfJSSE provider verified at position " +
            jssePos);
    }

    /**
     * Verify that the system CA certificates keystore is in WKS
     * (WolfSSLKeyStore) format rather than JKS format. This is required for
     * FIPS compliance since JKS/PKCS12 formats from Sun providers do not
     * use wolfCrypt FIPS or FIPS compliant cryptography.
     *
     * This KeyStore should have been converted during build of this base
     * image, so this is simply a sanity check on that prior to container
     * startup.
     *
     * @throws SecurityException if the cacerts file is not in WKS format or
     *         cannot be loaded properly.
     */
    public void verifyCACertificatesAreWKSFormat() throws SecurityException {

        System.out.println("\nVerifying system CA certs are in WKS format...");

        String javaHome = System.getProperty("java.home");
        String cacertsPath = javaHome + "/lib/security/cacerts";

        System.out.println("\tChecking cacerts file: " + cacertsPath);

        try {
            /* Try to load as WKS keystore first */
            KeyStore wksStore = KeyStore.getInstance("WKS");
            try (FileInputStream fis = new FileInputStream(cacertsPath)) {
                wksStore.load(fis, "changeitchangeit".toCharArray());
                int certCount = wksStore.size();
                System.out.println("\tSuccessfully loaded " + certCount +
                    " certificates from WKS format cacerts");
            }

        } catch (Exception wksException) {
            /* If WKS loading failed, try JKS to confirm wrong format */
            try {
                KeyStore jksStore = KeyStore.getInstance("JKS");
                try (FileInputStream fis = new FileInputStream(cacertsPath)) {
                    jksStore.load(fis, "changeit".toCharArray());
                    throw new SecurityException(
                        "ERROR: System cacerts file is in JKS format but " +
                        "should be WKS format for FIPS compliance! " +
                        "The CA certificate conversion process may " +
                        "have failed during container build.");
                }
            } catch (SecurityException se) {
                /* Re-throw our security exception */
                throw se;
            } catch (Exception jksException) {
                /* Neither WKS nor JKS worked */
                throw new SecurityException(
                    "Unable to load system cacerts file as either WKS " +
                    "or JKS format. WKS error: " + wksException.getMessage() +
                    "; JKS error: " + jksException.getMessage());
            }
        }

        System.out.println("\tSystem CA certificates verified as WKS format");
    }

    /**
     * Force a POST run for wolfCrypt FIPS by initializing and using a
     * Java object from one of the providers, in this case just a simple
     * MessageDigest should do.
     *
     * @throws SecurityException if the POST fails or encounters another
     *         problem.
     */
    public void forceRunPOST() throws SecurityException,
        NoSuchAlgorithmException {

        /* Test basic provider functionality to trigger FIPS POST */
        System.out.println("\nForcing FIPS POST via MessageDigest invocation");

        /* Test JCE provider with a simple hash operation */
        Provider wolfJCE = Security.getProvider("wolfJCE");
        MessageDigest md = MessageDigest.getInstance("SHA-256", wolfJCE);
        md.digest("FIPS POST test".getBytes());

        System.out.println("\tFIPS POST test completed successfully");
    }

    /**
     * Perform sanity checks on the java.security configuration file to ensure
     * that the expected security providers are registered and that no
     * unexpected providers are present.
     *
     * @throws SecurityException if any critical security provider violations
     *         are found in the java.security configuration file.
     * @throws IOException if there is an error reading the java.security file.
     */
    public void javaSecuritySanityChecks()
        throws SecurityException, IOException {

        String javaHome = System.getProperty("java.home");
        Path securityFile = Paths.get(javaHome, "conf",
            "security", "java.security");

        System.out.println("\nRunning sanity checks on java.security");
        System.out.println("\tReading from: " + securityFile.toString());

        /* Read all security provider lines from java.security that
         * are not commented out */
        List<String> lines = Files.readAllLines(securityFile);

        Map<Integer, String> providers = new TreeMap<>();
        Map<Integer, String> disabledProviders = new TreeMap<>();

        Pattern providerPattern = Pattern.compile(
            "^\\s*security\\.provider\\.(\\d+)\\s*=\\s*(.+)$");
        Pattern commentedProviderPattern = Pattern.compile(
            "^\\s*#\\s*security\\.provider\\.(\\d+)\\s*=\\s*(.+)$");

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }

            Matcher yesMatcher = providerPattern.matcher(line);
            Matcher noMatcher = commentedProviderPattern.matcher(line);

            if (yesMatcher.matches()) {
                int priority = Integer.parseInt(yesMatcher.group(1));
                String providerClass = yesMatcher.group(2).trim();
                providers.put(priority, providerClass);
            }
            else if (noMatcher.matches()) {
                int priority = Integer.parseInt(noMatcher.group(1));
                String providerClass = noMatcher.group(2).trim();
                disabledProviders.put(priority, providerClass);
            }
        }

        if (providers.isEmpty()) {
            throw new SecurityException("No security providers found in " +
                "java.security configuration file!");
        }

        System.out.println(
            "\tActive security providers (from java.security file):");

        boolean violationsFound = false;
        for (Map.Entry<Integer, String> entry : providers.entrySet()) {
            String status = "";
            String provider = entry.getValue();

            /* Mark status of known providers, and flag if known violation */
            if (provider.contains("WolfSSL") ||
                provider.contains("WolfCrypt")) {
                status = "   [Expected / FIPS]";

            /* Our filtered / wrapped providers around system ones */
            } else if (provider.equals(
                "com.wolfssl.security.providers.FilteredSun")) {
                status = "   [Expected / filtered Sun provider]";
            } else if (provider.equals(
                "com.wolfssl.security.providers.FilteredSunRsaSign")) {
                status = "   [Expected / filtered SunRsaSign provider]";
            } else if (provider.equals(
                "com.wolfssl.security.providers.FilteredSunEC")) {
                status = "   [Expected / filtered SunEC provider]";

            /* Providers we shouldn't see, mark violation if so */
            } else if (provider.contains("SunJCE")) {
                status = ">> [CRITICAL / Not Expected]";
                violationsFound = true;
            } else if (provider.contains("SunJSSE")) {
                status = ">> [CRITICAL / Not Expected]";
                violationsFound = true;
            } else if (provider.contains("SunPKCS11")) {
                status = ">> [CRITICAL / Not Expected]";
                violationsFound = true;
            } else if (provider.contains("SunPCSC")) {
                status = ">> [CRITICAL / could use SC crypto via PKCS#11]";
                violationsFound = true;
            } else if (provider.contains("SunRsaSign")) {
                status = ">> [CRITICAL / Only FilteredSunRsaSign expected]";
                violationsFound = true;
            } else if (provider.contains("SunEC")) {
                status = ">> [CRITICAL / Only FilteredSunEC expected]";
                violationsFound = true;

            /* Acceptable providers that don't implement crypto */
            } else if (provider.contains("SunJGSS")) {
                status = "   [GSS-API/Kerberos, delgates to JCE]";
            } else if (provider.contains("SunSASL")) {
                status = "   [SASL, delgates to JCE]";
            } else if (provider.contains("XMLDSig")) {
                status = "   [XML Digital Signature, delgates to JCE]";
            } else if (provider.contains("JdkLDAP")) {
                status = "   [JDK LDAP, delegates to JSSE for LDAPS]";
            } else if (provider.contains("JdkSASL")) {
                status = "   [JDK SASL, delegates to JCE]";

            /* Catch everything else for evaluation */
            } else {
                status = ">> [Unknown / Not Expected - needs evaluation and " +
                    "update of FipsInitCheck.java]";
                violationsFound = true;
            }

            System.out.printf("\t%2d. %-60s%s%n", entry.getKey(),
                provider, status);
        }

        if (violationsFound) {
            throw new SecurityException("Critical security provider " +
                "violations found in java.security configuration file!");
        }

        System.out.println();

        System.out.println("\tCommented/disabled security providers " +
            "(from java.security file):");

        if (disabledProviders.isEmpty()) {
            System.out.println("\tNo disabled security providers found.");
        } else {
            for (Map.Entry<Integer, String> entry :
                    disabledProviders.entrySet()) {
                System.out.printf("\t%2d. %-60s   [DISABLED]%n", entry.getKey(),
                    entry.getValue());
            }
        }
    }

    /**
     * Test that for all FIPS validated algorithms, the provider of that
     * service class is wolfJCE. This makes sure another provider is not
     * slipping through to provide each tested FIPS algorithm.
     *
     * Creates instances using generic getInstance() calls (without specifying
     * provider) and verifies the returned object uses the expected
     * wolfSSL provider.
     *
     * This also spot checks algorithms that should not be available in
     * a FIPS validated wolfCrypt are also not available via Java
     * services (ex: MessageDigest.MD5).
     *
     * @throws SecurityException if any algorithm fails to instantiate with
     *         the expected wolfSSL provider.
     */
    public void javaFIPSAlgorithmAvailabilityChecks()
        throws SecurityException {

        int testCount = 0;
        int passCount = 0;

        System.out.println(
            "\nTesting wolfSSL algorithm class instantiation...");

        /* MessageDigest - FIPS and non-FIPS validated algorithms */
        String[] fipsApprovedDigests = {
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        };
        String[] nonFipsDigests = { "MD5" };

        /* Mac - FIPS and non-FIPS validated algorithms */
        String[] fipsApprovedMacs = {
            "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384",
            "HmacSHA512", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384",
            "HmacSHA3-512", "AESCMAC", "AES-CMAC", "AESGMAC", "AES-GMAC"
        };
        String[] nonFipsMacs = { "HmacMD5" };

        /* Cipher - FIPS and non-FIPS validated algorithms */
        String[] fipsApprovedCiphers = {
            "AES/CBC/NoPadding", "AES/CBC/PKCS5Padding",
            "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding",
            "AES/CTR/NoPadding",
            "AES/OFB/NoPadding",
            "AES/GCM/NoPadding",
            "AES/CCM/NoPadding",
            "RSA", "RSA/ECB/PKCS1Padding"
        };
        String[] nonFipsCiphers = {
            "DES/CBC/NoPadding",
            "DESede/CBC/NoPadding",
            "DESede/ECB/NoPadding"
        };

        /* Signature - FIPS and non-FIPS validated algorithms */
        String[] fipsApprovedSignatures = {
            "SHA1withRSA",
            "SHA224withRSA",
            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "SHA1withECDSA",
            "SHA224withECDSA",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA",
            "SHA3-224withRSA",
            "SHA3-256withRSA",
            "SHA3-384withRSA",
            "SHA3-512withRSA",
            "SHA3-224withECDSA",
            "SHA3-256withECDSA",
            "SHA3-384withECDSA",
            "SHA3-512withECDSA",
            "RSASSA-PSS",
            "SHA224withRSA/PSS",
            "SHA256withRSA/PSS",
            "SHA384withRSA/PSS",
            "SHA512withRSA/PSS"
        };
        String[] nonFipsSignatures = {
            "MD5withRSA"
        };

        /* SSLContext protocols */
        String[] sslContexts = {
            "DEFAULT", "SSL", "TLS", "TLSv1.2", "TLSv1.3"
        };

        /* KeyManagerFactory algorithms */
        String[] keyManagerFactories = {
            "PKIX", "X509", "SunX509"
        };

        /* TrustManagerFactory algorithms */
        String[] trustManagerFactories = {
            "PKIX", "X509", "SunX509"
        };

        /* MessageDigest - FIPS approved algorithms */
        for (String alg : fipsApprovedDigests) {
            testCount++;
            try {
                MessageDigest md = MessageDigest.getInstance(alg);
                String providerName = md.getProvider().getName();
                if ("wolfJCE".equals(providerName)) {
                    System.out.println("\tMessageDigest: " + alg +
                        " -> " + providerName);
                    passCount++;
                } else {
                    throw new SecurityException("MessageDigest: " + alg +
                        " using wrong provider: " + providerName +
                        " (expected wolfJCE)");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Failed to create MessageDigest: " + alg + ": " +
                    e.getMessage());
            }
        }

        /* MessageDigest - Non-approved Algorithms */
        for (String alg : nonFipsDigests) {
            testCount++;
            try {
                MessageDigest md = MessageDigest.getInstance(alg);
                String providerName = md.getProvider().getName();
                throw new SecurityException(
                    "FIPS violation: MessageDigest: " + alg +
                    " should NOT be available in FIPS mode but was " +
                    "provided by " + providerName);
            } catch (Exception e) {
                /* Expected behavior - algorithm should not be available */
                System.out.println("\tMessageDigest: " + alg +
                    " -> UNAVAILABLE (correctly not available in FIPS mode)");
                passCount++;
            }
        }

        /* Mac - FIPS approved algorithms */
        for (String alg : fipsApprovedMacs) {
            testCount++;
            try {
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance(alg);
                String providerName = mac.getProvider().getName();
                if ("wolfJCE".equals(providerName)) {
                    System.out.println("\tMac: " + alg + " -> " + providerName);
                    passCount++;
                } else {
                    throw new SecurityException("Mac: " + alg +
                        " using wrong provider: " + providerName +
                        " (expected wolfJCE)");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Failed to create Mac: " + alg + ": " + e.getMessage());
            }
        }

        /* Mac - Non-approved Algorithms */
        for (String alg : nonFipsMacs) {
            testCount++;
            try {
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance(alg);
                String providerName = mac.getProvider().getName();
                throw new SecurityException("FIPS violation: Mac: " + alg +
                    " should NOT be available in FIPS mode but was " +
                    "provided by " + providerName);
            } catch (Exception e) {
                /* Expected behavior - algorithm should not be available */
                System.out.println("\tMac: " + alg + " -> UNAVAILABLE " +
                    "(correctly not available in FIPS mode)");
                passCount++;
            }
        }

        /* Cipher - FIPS approved algorithms */
        for (String alg : fipsApprovedCiphers) {
            testCount++;
            try {
                javax.crypto.Cipher cipher =
                    javax.crypto.Cipher.getInstance(alg);
                String providerName = cipher.getProvider().getName();
                if ("wolfJCE".equals(providerName)) {
                    System.out.println("\tCipher: " + alg + " -> " +
                        providerName);
                    passCount++;
                } else {
                    throw new SecurityException("Cipher: " + alg +
                        " using wrong provider: " + providerName +
                        " (expected wolfJCE)");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Failed to create Cipher: " + alg + ": " + e.getMessage());
            }
        }

        /* Cipher - Non-approved Algorithms */
        for (String alg : nonFipsCiphers) {
            testCount++;
            try {
                Cipher cipher = Cipher.getInstance(alg);
                String providerName = cipher.getProvider().getName();
                throw new SecurityException("FIPS violation: Cipher: " + alg +
                    " should NOT be available in FIPS mode but was " +
                    "provided by " + providerName);
            } catch (Exception e) {
                /* Expected behavior - algorithm should not be available */
                System.out.println("\tCipher: " + alg + " -> UNAVAILABLE " +
                    "(correctly not available in FIPS mode)");
                passCount++;
            }
        }

        /* Signature - FIPS approved algorithms */
        for (String alg : fipsApprovedSignatures) {
            testCount++;
            try {
                Signature sig = Signature.getInstance(alg);
                String providerName = sig.getProvider().getName();
                if ("wolfJCE".equals(providerName)) {
                    System.out.println("\tSignature: " + alg + " -> " +
                        providerName);
                    passCount++;
                } else {
                    throw new SecurityException("Signature: " + alg +
                        " using wrong provider: " + providerName +
                        " (expected wolfJCE)");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Failed to create Signature: " + alg + ": " +
                    e.getMessage());
            }
        }

        /* Signature - Non-approved Algorithms */
        for (String alg : nonFipsSignatures) {
            testCount++;
            try {
                Signature sig = Signature.getInstance(alg);
                String providerName = sig.getProvider().getName();
                throw new SecurityException("FIPS violation: Signature: " +
                    alg + " should NOT be available in FIPS mode but " +
                    "was provided by " + providerName);
            } catch (Exception e) {
                /* Expected behavior - algorithm should not be available */
                System.out.println("\tSignature: " + alg + " -> UNAVAILABLE " +
                    "(correctly not available in FIPS mode)");
                passCount++;
            }
        }

        /* SSLContext protocols */
        for (String protocol : sslContexts) {
            testCount++;
            try {
                SSLContext ctx = SSLContext.getInstance(protocol);
                String providerName = ctx.getProvider().getName();
                if ("wolfJSSE".equals(providerName)) {
                    System.out.println("\tSSLContext: " + protocol + " -> " +
                        providerName);
                    passCount++;
                } else {
                    throw new SecurityException("SSLContext: " + protocol +
                        " using wrong provider: " + providerName +
                        " (expected wolfJSSE)");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Failed to create SSLContext: " + protocol + ": " +
                    e.getMessage());
            }
        }

        /* KeyManagerFactory algorithms */
        for (String alg : keyManagerFactories) {
            testCount++;
            try {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(alg);
                String providerName = kmf.getProvider().getName();
                if ("wolfJSSE".equals(providerName)) {
                    System.out.println("\tKeyManagerFactory: " + alg +
                        " -> " + providerName);
                    passCount++;
                } else {
                    throw new SecurityException("KeyManagerFactory: " + alg +
                        " using wrong provider: " + providerName +
                        " (expected wolfJSSE)");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Failed to create KeyManagerFactory: " + alg + ": " +
                    e.getMessage());
            }
        }

        /* TrustManagerFactory algorithms */
        for (String alg : trustManagerFactories) {
            testCount++;
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(alg);
                String providerName = tmf.getProvider().getName();
                if ("wolfJSSE".equals(providerName)) {
                    System.out.println("\tTrustManagerFactory: " + alg +
                        " -> " + providerName);
                    passCount++;
                } else {
                    throw new SecurityException("TrustManagerFactory: " + alg +
                        " using wrong provider: " + providerName +
                        " (expected wolfJSSE)");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Failed to create TrustManagerFactory: " + alg + ": " +
                    e.getMessage());
            }
        }

        System.out.println("\n\tAlgorithm class instantiation results:");
        System.out.println("\t\tTests passed: " + passCount + "/" + testCount);

        if (passCount != testCount) {
            throw new SecurityException(
                "Algorithm class instantiation tests failed: " +
                (testCount - passCount) + " failures out of " + testCount +
                " tests");
        }

        System.out.println("\tAll expected FIPS algorithm classes " +
            "instantiated successfully with correct providers");
    }

    /**
     * Verify that all available JCA algorithms/services are provided by
     * wolfJCE (for JCE services) or wolfJSSE (for JSSE services).
     * This ensures no non-FIPS algorithms slip through via other providers.
     *
     * @throws SecurityException if any algorithm/service is provided by
     *         a non-wolfSSL provider
     */
    public void verifyAllAlgorithmsUseWolfSSLProviders()
        throws SecurityException {

        System.out.println(
            "\nVerifying all JCA algorithms use wolfSSL providers...");

        Provider[] providers = Security.getProviders();
        int totalViolations = 0;
        int totalChecked = 0;

        /* JCE service types that should use wolfJCE */
        String[] jceServiceTypes = {
            "MessageDigest", "Mac", "Cipher", "Signature", "KeyGenerator",
            "KeyPairGenerator", "KeyAgreement", "SecretKeyFactory",
            "AlgorithmParameterGenerator", "SecureRandom"
        };

        /* JSSE service types that should use wolfJSSE */
        String[] jsseServiceTypes = {
            "SSLContext", "KeyManagerFactory", "TrustManagerFactory"
        };

        /* Non-cryptographic service types that can use filtered providers */
        String[] allowedNonCryptoServiceTypes = {
            "AlgorithmParameters", "CertificateFactory", "CertPathBuilder",
            "CertPathValidator", "CertStore", "KeyStore", "KeyFactory",
            "Policy", "Configuration"
        };

        /* Check JCE services - must use wolfJCE */
        for (String serviceType : jceServiceTypes) {
            totalViolations +=
                checkServiceTypeProvider(serviceType, "wolfJCE", providers);
            totalChecked++;
        }

        /* Check JSSE services - must use wolfJSSE */
        for (String serviceType : jsseServiceTypes) {
            totalViolations +=
                checkServiceTypeProvider(serviceType, "wolfJSSE", providers);
            totalChecked++;
        }

        /* Check non-cryptographic services - can use filtered
         * providers or wolfSSL */
        for (String serviceType : allowedNonCryptoServiceTypes) {
            totalViolations +=
                checkNonCryptoServiceTypeProvider(serviceType, providers);
            totalChecked++;
        }

        System.out.println("\tService type verification results:");
        System.out.println("\t\tService types checked: " + totalChecked);
        System.out.println("\t\tViolations found: " + totalViolations);

        if (totalViolations > 0) {
            throw new SecurityException("Found " + totalViolations +
                " service types with algorithms provided by " +
                "non-wolfSSL providers!");
        }

        System.out.println(
            "\tAll JCA algorithms verified to use wolfSSL providers");
    }

    /**
     * Check that all algorithms for a specific service type are provided by
     * the expected wolfSSL provider.
     *
     * @param serviceType The service type to check
     * @param expectedProvider The expected provider name
     *        ("wolfJCE" or "wolfJSSE")
     * @param providers Array of all security providers
     *
     * @return Number of violations found
     */
    private int checkServiceTypeProvider(String serviceType,
        String expectedProvider, Provider[] providers) {

        int violations = 0;
        Set<String> algorithms = Security.getAlgorithms(serviceType);

        System.out.println("\t" + serviceType + " algorithms (" +
            algorithms.size() + " found):");

        for (String algorithm : algorithms) {
            String actualProvider =
                findProviderForAlgorithm(serviceType, algorithm);

            if (expectedProvider.equals(actualProvider)) {
                System.out.println("\t\t" + algorithm + " -> " +
                    actualProvider);
            } else {
                System.out.println("\t\t" + algorithm + " -> " +
                    actualProvider + " (expected " + expectedProvider + ")");
                violations++;
            }
        }

        return violations;
    }

    /**
     * Check non-cryptographic service types that can be provided by filtered
     * providers or wolfSSL providers.
     *
     * @param serviceType The service type to check
     * @param providers Array of all security providers
     *
     * @return Number of violations found
     */
    private int checkNonCryptoServiceTypeProvider(String serviceType,
        Provider[] providers) {

        int violations = 0;
        Set<String> algorithms = Security.getAlgorithms(serviceType);

        System.out.println("\t" + serviceType + " algorithms (" +
            algorithms.size() + " found):");

        for (String algorithm : algorithms) {
            String actualProvider =
                findProviderForAlgorithm(serviceType, algorithm);

            /* Allow wolfSSL providers, filtered providers,
             * and non-crypto providers */
            if ("wolfJCE".equals(actualProvider) ||
                "wolfJSSE".equals(actualProvider) ||
                "FilteredSun".equals(actualProvider) ||
                "FilteredSunRsaSign".equals(actualProvider) ||
                "FilteredSunEC".equals(actualProvider) ||
                "JdkLDAP".equals(actualProvider)) {

                System.out.println("\t\t" + algorithm + " -> " +
                    actualProvider);
            } else {
                System.out.println("\t\t" + algorithm + " -> " +
                    actualProvider + " (non-approved provider)");
                violations++;
            }
        }

        return violations;
    }

    /**
     * Find which provider is offering a specific algorithm for a given
     * service type.
     *
     * @param serviceType The service type (e.g., "MessageDigest", "Cipher")
     * @param algorithm The algorithm name
     * @return The name of the provider offering this algorithm
     */
    private String findProviderForAlgorithm(String serviceType,
        String algorithm) {

        Provider[] providers = Security.getProviders();

        for (Provider provider : providers) {
            /* Check if this provider offers the algorithm for the given
             * service type */
            if (provider.getService(serviceType, algorithm) != null) {
                return provider.getName();
            }
        }

        return "UNKNOWN";
    }

    /**
     * Additional FIPS security compliance sanity checks:
     * 1. SecureRandom.getInstanceStrong() uses wolfSSL provider
     * 2. SSLContext.getDefault() uses wolfSSL provider
     * 3. Spot check a few banned cipher suites are rejected
     * 4. Spot check restricted algorithms like X25519 are unavailable
     *
     * @throws SecurityException if any security test fails
     */
    public void additionalFIPSSecurityTests() throws SecurityException {

        System.out.println(
            "\nRunning additional FIPS security compliance tests...");

        /* SecureRandom.getInstanceStrong() should use wolfSSL */
        testSecureRandomStrongUsesWolfSSL();

        /* SSLContext.getDefault() should use wolfSSL */
        testSSLContextDefaultUsesWolfSSL();

        /* Banned cipher suites should be rejected */
        testBannedCipherSuitesRejected();

        /* Restricted algorithms should be unavailable */
        testRestrictedAlgorithmsUnavailable();

        System.out.println("\tAll additional FIPS security tests passed");
    }

    /**
     * Test SecureRandom.getInstanceStrong() uses wolfSSL provider
     */
    private void testSecureRandomStrongUsesWolfSSL()
        throws SecurityException {

        try {
            SecureRandom strongRandom = SecureRandom.getInstanceStrong();
            String providerName = strongRandom.getProvider().getName();

            if (providerName.contains("wolf")) {
                System.out.println(
                    "\tSecureRandom.getInstanceStrong() -> " + providerName);
            } else {
                throw new SecurityException(
                    "SecureRandom.getInstanceStrong() using non-wolfSSL " +
                    "provider: " + providerName +
                    " (expected wolfSSL provider)");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(
                "Failed to get SecureRandom.getInstanceStrong(): " +
                e.getMessage());
        }
    }

    /**
     * Test SSLContext.getDefault() uses wolfSSL provider
     */
    private void testSSLContextDefaultUsesWolfSSL()
        throws SecurityException {

        try {
            SSLContext defaultContext = SSLContext.getDefault();
            String providerName = defaultContext.getProvider().getName();

            if (providerName.contains("wolf")) {
                System.out.println("\tSSLContext.getDefault() -> " +
                    providerName);
            } else {
                throw new SecurityException(
                    "SSLContext.getDefault() using non-wolfSSL provider: " +
                    providerName + " (expected wolfSSL provider)");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(
                "Failed to get SSLContext.getDefault(): " + e.getMessage());
        }
    }

    /**
     * Spot check non-compliant cipher suites like 3DES are properly rejected
     */
    private void testBannedCipherSuitesRejected()
        throws SecurityException {

        String[] bannedSuites = {
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_RSA_WITH_3DES_EDE_CBC_SHA"
        };

        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            SSLSocketFactory factory = context.getSocketFactory();
            String[] supportedSuites = factory.getSupportedCipherSuites();

            for (String bannedSuite : bannedSuites) {
                boolean found = false;
                for (String supportedSuite : supportedSuites) {
                    if (supportedSuite.equals(bannedSuite)) {
                        found = true;
                        break;
                    }
                }

                if (found) {
                    throw new SecurityException(
                        "FIPS violation: Banned cipher suite " + bannedSuite +
                        " is available but should be rejected in FIPS mode");
                } else {
                    System.out.println("\tBanned cipher suite " + bannedSuite +
                        " -> UNAVAILABLE");
                }
            }
        } catch (Exception e) {
            if (e instanceof SecurityException) {
                throw (SecurityException) e;
            }
            throw new SecurityException(
                "Failed to test banned cipher suites: " + e.getMessage());
        }
    }

    /**
     * Spot check restricted algorithms like X25519 are unavailable
     */
    private void testRestrictedAlgorithmsUnavailable()
        throws SecurityException {

        String[] restrictedAlgorithms = {
            "X25519",
            "X448"
        };

        for (String algorithm : restrictedAlgorithms) {
            try {
                AlgorithmParameters.getInstance(algorithm);
                throw new SecurityException(
                    "FIPS violation: Restricted algorithm " + algorithm +
                    " should not be available");
            } catch (NoSuchAlgorithmException e) {
                /* Expected behavior - algorithm should not be available */
                System.out.println("\tRestricted algorithm " + algorithm +
                    " -> UNAVAILABLE");
            } catch (Exception e) {
                if (e instanceof SecurityException) {
                    throw (SecurityException) e;
                }
                throw new SecurityException(
                    "Unexpected error testing restricted algorithm " +
                    algorithm + ": " + e.getMessage());
            }
        }
    }
}

