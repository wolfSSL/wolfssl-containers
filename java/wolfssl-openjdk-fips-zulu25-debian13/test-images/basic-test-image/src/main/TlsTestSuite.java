/* TlsTestSuite.java
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
import java.security.cert.*;
import javax.net.ssl.*;
import javax.net.ssl.SNIHostName;

/**
 * SSL/TLS tests for the wolfSSL FIPS container. Checks that the JSSE
 * services come from wolfJSSE, and connects to public HTTPS endpoints.
 */
public class TlsTestSuite {

    private static final String PROVIDER_WOLFJSSE = "wolfJSSE";

    /* Public HTTPS endpoints for the connection tests */
    private static final String[] TEST_ENDPOINTS = {
        "www.google.com:443",
        "www.wolfssl.com:443",
        "httpbin.org:443"
    };

    public static void main(String[] args) {
        TlsTestSuite suite = new TlsTestSuite();
        suite.runAllTests();
    }

    public void runAllTests() {
        System.out.println("=== wolfSSL FIPS SSL/TLS Test Suite ===\n");

        System.out.println("Debug configuration:");
        System.out.println("  wolfjce.debug system property: " +
            System.getProperty("wolfjce.debug"));
        System.out.println("  wolfjsse.debug system property: " +
            System.getProperty("wolfjsse.debug"));
        System.out.println("  WOLFJCE_DEBUG env var: " +
            System.getenv("WOLFJCE_DEBUG"));
        System.out.println("  WOLFJSSE_DEBUG env var: " +
            System.getenv("WOLFJSSE_DEBUG"));

        /* Set the debug properties from the environment variables */
        if ("true".equals(System.getenv("WOLFJCE_DEBUG"))) {
            System.setProperty("wolfjce.debug", "true");
            System.out.println("  Manually enabled wolfjce.debug from env var");
        }
        if ("true".equals(System.getenv("WOLFJSSE_DEBUG"))) {
            System.setProperty("wolfjsse.debug", "true");
            System.out.println("  Manually enabled wolfjsse.debug from env var");
        }
        System.out.println();

        try {
            verifyProviderSetup();
            testSslContextCreation();
            testTlsConnections();
            testSslSocketCreation();
            testCertificateValidation();
            testTlsProtocolVersions();
            testCipherSuites();

            System.out.println("\n=== All SSL/TLS Tests PASSED ===");

        } catch (Exception e) {
            System.err.println("\nERROR: SSL/TLS test failed!");
            System.err.println("Exception: " + e.getClass().getName() +
                ": " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void verifyProviderSetup()
        throws SecurityException {

        System.out.println("Verifying wolfJSSE Provider Setup:");

        Provider wolfJSSE = Security.getProvider(PROVIDER_WOLFJSSE);
        if (wolfJSSE == null) {
            throw new SecurityException("wolfJSSE provider not found");
        }

        System.out.println("   wolfJSSE provider found: " +
            wolfJSSE.getName() + " v" + wolfJSSE.getVersion());
        System.out.println("   Provider info: " + wolfJSSE.getInfo());
        System.out.println();
    }

    private void testSslContextCreation()
        throws Exception {

        System.out.println("Testing SSLContext Creation:");

        String[] protocols = {"TLS", "TLSv1.2", "TLSv1.3", "DEFAULT"};

        for (String protocol : protocols) {
            SSLContext context = SSLContext.getInstance(protocol);

            if (!PROVIDER_WOLFJSSE.equals(context.getProvider().getName())) {
                throw new SecurityException("SSLContext " + protocol +
                    " not using wolfJSSE provider");
            }

            /* Initialize with default trust managers */
            context.init(null, null, null);

            System.out.println("   SSLContext " + protocol +
                ": Created and initialized (wolfJSSE)");
        }
        System.out.println();
    }

    private void testTlsConnections()
        throws Exception {

        System.out.println("Testing TLS Connections to Public Endpoints:");
        System.out.println(
            "   Using WKS system cacerts for certificate validation");

        /* Load the WKS system cacerts explicitly */
        String javaHome = System.getProperty("java.home");
        String cacertsPath = javaHome + "/lib/security/cacerts";

        KeyStore trustStore = KeyStore.getInstance("WKS");
        try (FileInputStream fis = new FileInputStream(cacertsPath)) {
            trustStore.load(fis, "changeitchangeit".toCharArray());
            System.out.println("   Loaded " + trustStore.size() +
                " CA certificates from WKS cacerts");
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        SSLSocketFactory factory = context.getSocketFactory();

        int failureCount = 0;
        Exception lastException = null;

        for (String endpoint : TEST_ENDPOINTS) {
            String[] parts = endpoint.split(":");
            String host = parts[0];
            int port = Integer.parseInt(parts[1]);

            try {
                System.out.println("   Testing connection to " +
                    endpoint + "...");

                SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
                socket.setSoTimeout(10000); /* 10 second timeout */

                /* Set SNI so the server returns the right certificate */
                SSLParameters sslParams = socket.getSSLParameters();
                sslParams.setServerNames(Arrays.asList(new SNIHostName(host)));
                socket.setSSLParameters(sslParams);

                socket.startHandshake();

                SSLSession session = socket.getSession();
                System.out.println("     TLS handshake successful");
                System.out.println("     Protocol: " + session.getProtocol());
                System.out.println("     Cipher Suite: " +
                    session.getCipherSuite());
                System.out.println("     Peer certificates: " +
                    session.getPeerCertificates().length);

                inspectCertificateChain(
                    session.getPeerCertificates(), "     ");

                testHttpsRequest(socket, host);

                socket.close();
                System.out.println("     Connection closed successfully");

            } catch (Exception e) {
                failureCount++;
                lastException = e;
                String message = e.getMessage();
                System.out.println("     Connection failed: " + message);

                /* Categorize the type of failure */
                if (message != null) {
                    if (message.contains("error code: -140")) {
                        System.out.println("     ASN.1 parsing error: " +
                            "Certificate uses unsupported " +
                            "algorithms/structures");
                        System.out.println("     This may indicate " +
                            "Ed25519/Ed448 signatures or other non-FIPS " +
                            "algorithms");
                        System.out.println("     wolfSSL FIPS build may not " +
                            "include required ASN.1 parsers");
                    } else if (message.contains("error code: -275")) {
                        System.out.println("     Self-signed certificate " +
                            "error: May indicate SNI or chain validation " +
                            "issues");
                        System.out.println("     Check if proper certificate " +
                            "is being served for this hostname");
                    } else if (message.contains("certificate") ||
                               message.contains("ASN") ||
                        message.contains("error code: -188")) {
                        System.out.println("     Certificate validation " +
                            "failed");
                        System.out.println("     This may indicate " +
                            "certificate chain or validation issues");
                        System.out.println("     wolfJSSE TLS stack is " +
                            "working but certificate validation failed");
                    } else if (message.contains("Connection refused") ||
                               message.contains("timeout")) {
                        System.out.println("     Network connectivity issue");
                    } else {
                        System.out.println("     Other SSL/TLS issue: " +
                            e.getClass().getSimpleName());
                    }
                } else {
                    System.out.println("     SSL/TLS connection failed");
                }
                System.out.println("     wolfJSSE provider is functioning " +
                    "for TLS operations");

                /* Show the chain even though validation failed */
                System.out.println("     Attempting to retrieve certificate " +
                    "chain for analysis...");
                inspectCertificateChainOnFailure(host, port);
            }
        }

        if (failureCount > 0) {
            System.out.println("   FAILURE SUMMARY:");
            System.out.println("   " + failureCount + " out of " +
                TEST_ENDPOINTS.length + " TLS connections failed");
            throw new SecurityException("TLS connection failures. " +
                "Last error: " + (lastException != null ?
                    lastException.getMessage() : "Unknown"));
        }

        System.out.println("   All TLS connections successful - FIPS " +
            "certificate validation working correctly");
        System.out.println();
    }

    private void testHttpsRequest(SSLSocket socket, String host)
        throws Exception {

        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(
            new InputStreamReader(socket.getInputStream()));

        out.println("GET / HTTP/1.1");
        out.println("Host: " + host);
        out.println("Connection: close");
        out.println();

        String line;
        boolean foundStatusLine = false;
        while ((line = in.readLine()) != null && !line.isEmpty()) {
            if (line.startsWith("HTTP/")) {
                System.out.println("     HTTP Response: " + line);
                foundStatusLine = true;
                break;
            }
        }

        if (!foundStatusLine) {
            throw new Exception("No valid HTTP response received");
        }
    }

    private void testSslSocketCreation()
        throws Exception {

        System.out.println("Testing SSL Socket Creation:");

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        SSLSocketFactory factory = context.getSocketFactory();

        /* Test socket creation without connection */
        SSLSocket socket = (SSLSocket) factory.createSocket();

        System.out.println("   SSL Socket created successfully");
        System.out.println("   Supported protocols: " +
            Arrays.toString(socket.getSupportedProtocols()));
        System.out.println("   Enabled protocols: " +
            Arrays.toString(socket.getEnabledProtocols()));
        System.out.println("   Supported cipher suites: " +
            socket.getSupportedCipherSuites().length + " available");

        socket.close();
        System.out.println();
    }

    private void testCertificateValidation()
        throws Exception {

        System.out.println("Testing Certificate Validation:");

        /* Load WKS system cacerts explicitly */
        String javaHome = System.getProperty("java.home");
        String cacertsPath = javaHome + "/lib/security/cacerts";

        KeyStore trustStore = KeyStore.getInstance("WKS");
        try (FileInputStream fis = new FileInputStream(cacertsPath)) {
            trustStore.load(fis, "changeitchangeit".toCharArray());
            System.out.println("   Loaded " + trustStore.size() +
                " CA certificates from WKS cacerts");
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");

        if (!PROVIDER_WOLFJSSE.equals(tmf.getProvider().getName())) {
            throw new SecurityException(
                "TrustManagerFactory not using wolfJSSE provider");
        }

        tmf.init(trustStore);
        TrustManager[] trustManagers = tmf.getTrustManagers();

        System.out.println("   TrustManagerFactory created with wolfJSSE");
        System.out.println("   Trust managers initialized with WKS cacerts: " +
            trustManagers.length + " managers");

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");

        if (!PROVIDER_WOLFJSSE.equals(kmf.getProvider().getName())) {
            throw new SecurityException(
                "KeyManagerFactory not using wolfJSSE provider");
        }

        System.out.println("   KeyManagerFactory created with wolfJSSE");
        System.out.println();
    }

    private void testTlsProtocolVersions()
        throws Exception {

        System.out.println("Testing TLS Protocol Versions:");

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();

        String[] supportedProtocols = socket.getSupportedProtocols();
        String[] enabledProtocols = socket.getEnabledProtocols();

        System.out.println("   Supported TLS protocols:");
        for (String protocol : supportedProtocols) {
            System.out.println("     - " + protocol);
        }

        System.out.println("   Enabled TLS protocols:");
        for (String protocol : enabledProtocols) {
            System.out.println("     " + protocol);
        }

        boolean tls12Supported =
            Arrays.asList(supportedProtocols).contains("TLSv1.2");
        boolean tls13Supported =
            Arrays.asList(supportedProtocols).contains("TLSv1.3");

        if (!tls12Supported) {
            throw new SecurityException("TLS 1.2 not supported");
        }
        System.out.println("   TLS 1.2 support verified");

        if (!tls13Supported) {
            throw new SecurityException("TLS 1.3 not supported");
        }
        System.out.println("   TLS 1.3 support verified");

        socket.close();
        System.out.println();
    }

    private void testCipherSuites()
        throws Exception {

        System.out.println("Testing Cipher Suites:");

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();

        String[] supportedCipherSuites =
            socket.getSupportedCipherSuites();
        String[] enabledCipherSuites =
            socket.getEnabledCipherSuites();

        System.out.println("   Total supported cipher suites: " +
            supportedCipherSuites.length);
        System.out.println("   Total enabled cipher suites: " +
            enabledCipherSuites.length);

        int fipsAesCipherCount = 0;
        int fipsEcdheCipherCount = 0;

        System.out.println("   Enabled AES and ECDHE cipher suites:");
        for (String cipherSuite : enabledCipherSuites) {
            if (cipherSuite.contains("AES")) {
                fipsAesCipherCount++;
                System.out.println("     " + cipherSuite);
            } else if (cipherSuite.contains("ECDHE")) {
                fipsEcdheCipherCount++;
                System.out.println("     " + cipherSuite);
            }
        }

        if (fipsAesCipherCount == 0) {
            throw new SecurityException("No AES cipher suites enabled");
        }

        System.out.println("   AES cipher suites available: " +
            fipsAesCipherCount);
        System.out.println("   ECDHE cipher suites available: " +
            fipsEcdheCipherCount);

        socket.close();
        System.out.println();
    }

    /**
     * Print certificate chain details for debugging.
     */
    private void inspectCertificateChain(
        java.security.cert.Certificate[] certChain, String indent) {

        System.out.println(indent + "Certificate chain details:");

        for (int i = 0; i < certChain.length; i++) {
            if (certChain[i] instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) certChain[i];
                System.out.println(indent + "  [" + i + "] Subject: " +
                    cert.getSubjectX500Principal().getName());
                System.out.println(indent + "      Issuer: " +
                    cert.getIssuerX500Principal().getName());
                System.out.println(indent + "      Signature Algorithm: " +
                    cert.getSigAlgName());
                System.out.println(indent + "      Public Key Algorithm: " +
                    cert.getPublicKey().getAlgorithm());
                System.out.println(indent + "      Valid From: " +
                    cert.getNotBefore());
                System.out.println(indent + "      Valid To: " +
                    cert.getNotAfter());

                try {
                    boolean[] keyUsage = cert.getKeyUsage();
                    if (keyUsage != null) {
                        System.out.println(indent + "      Key Usage: " +
                            Arrays.toString(keyUsage));
                    }

                    int basicConstraints = cert.getBasicConstraints();
                    if (basicConstraints >= 0) {
                        System.out.println(indent +
                            "      Basic Constraints: CA=true, Path Length=" +
                            basicConstraints);
                    } else if (basicConstraints == -1) {
                        System.out.println(indent +
                            "      Basic Constraints: CA=false (end entity)");
                    }
                } catch (Exception e) {
                    System.out.println(indent +
                        "      Extension analysis failed: " + e.getMessage());
                }
            } else {
                System.out.println(indent + "  [" + i +
                    "] Non-X509 certificate: " +
                    certChain[i].getClass().getName());
            }
        }
    }

    /**
     * After a validation failure, reconnect with a trust-all manager to
     * print the server's certificate chain.
     */
    private void inspectCertificateChainOnFailure(String host, int port) {
        try {
            TrustManager[] permissiveTrustManagers = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs,
                        String authType) {
                        /* Accept all client certificates for inspection */
                    }
                    public void checkServerTrusted(X509Certificate[] certs,
                        String authType) {
                        System.out.println("       Retrieved " + certs.length +
                            " certificates for analysis");
                        inspectCertificateChain(certs, "       ");
                    }
                }
            };

            SSLContext permissiveContext = SSLContext.getInstance("TLS");
            permissiveContext.init(null, permissiveTrustManagers, null);

            SSLSocketFactory permissiveFactory =
                permissiveContext.getSocketFactory();
            SSLSocket permissiveSocket =
                (SSLSocket) permissiveFactory.createSocket(host, port);
            permissiveSocket.setSoTimeout(5000);

            /* Set SNI so the server returns the right certificate */
            SSLParameters sslParams = permissiveSocket.getSSLParameters();
            sslParams.setServerNames(Arrays.asList(new SNIHostName(host)));
            permissiveSocket.setSSLParameters(sslParams);

            /* The handshake calls checkServerTrusted(), which prints
             * the chain */
            permissiveSocket.startHandshake();

            permissiveSocket.close();

        } catch (Exception inspectionException) {
            System.out.println("       Certificate chain inspection failed: " +
                inspectionException.getMessage());
        }
    }
}

