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
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import javax.net.ssl.*;
import javax.crypto.*;

/**
 * Startup checks for the wolfSSL FIPS container. The container stops if any
 * check fails.
 *     - Lists the registered security providers (informational), marking
 *       SASL mechanisms that are disabled or cannot be used
 *     - Confirms wolfJCE is registered at priority 1 and wolfJSSE at 2
 *     - Confirms the wolfSSL providers come from the provider JARs in
 *       /usr/share/java and the native libraries from /usr/local/lib and
 *       /usr/lib/jni
 *     - Fails on JVM options that replace classes (module patching, boot
 *       class path additions)
 *     - Confirms the native wolfCrypt FIPS module state: a FIPS build
 *       (Fips.enabled), module version 5 for wolfCrypt FIPS v5.2.3
 *       (Fips.fipsVersion), passing algorithm self tests (CASTs), and no
 *       module error state (wolfCrypt_GetStatus_fips), checked again after
 *       all other checks
 *     - Confirms the system CA certificates are in WKS format
 *     - Runs the FIPS Power-On Self Test (POST) through a wolfJCE
 *       MessageDigest
 *     - Checks the security providers listed in java.security
 *     - Reports filtered provider grants (additionalServices) set in
 *       java.security, which the following checks allow
 *     - Checks the expected algorithms come from wolfJCE and wolfJSSE
 *     - Checks that algorithms outside the wolfCrypt FIPS v5.2.3 boundary
 *       are unavailable. KeyStore JKS / PKCS12 are allowed from
 *       wolfJCE when java.security maps them to WKS (wolfjce.mapJKStoWKS,
 *       wolfjce.mapPKCS12toWKS).
 *     - Lists every service of every registered provider, and verifies each
 *       one is allowed for its provider: wolfJCE and wolfJSSE may offer any
 *       service, the filtered Sun providers only exactly their listed services
 *       (all required), and the JDK delegating providers only their
 *       non-cryptographic service types
 *     - Confirms SecureRandom.getInstanceStrong() and SSLContext.getDefault()
 *       come from wolfJCE / wolfJSSE, lists the default SSLContext's TLS
 *       protocols (informational), and confirms it enables and supports no
 *       cipher suites with a cipher or MAC that is not in the wolfCrypt FIPS
 *       module
 *     - Reports whether TLS 1.2 requires the Extended Master Secret
 *       (jdk.tls.allowLegacyMasterSecret=false, set by the image), and
 *       confirms wolfJSSE and native wolfSSL can enforce it when required
 */
public class FipsInitCheck {

    public static void main(String[] args) {
        new FipsInitCheck().runTests();

        /* The entrypoint passes --pass-exit-code=N and requires exit code N,
         * so launcher options that exit before main() (such as -version)
         * cannot look like a passing run */
        for (String arg : args) {
            if (arg.startsWith("--pass-exit-code=")) {
                System.exit(Integer.parseInt(
                    arg.substring("--pass-exit-code=".length())));
            }
        }
    }

    public void runTests() {

        try {
            /* List the loaded providers (informational) */
            listAllRegisteredSecurityProviders();

            /* Ensure wolfJCE and wolfJSSE are registered at correct priority */
            confirmWolfSSLProvidersAreRegistered();

            /* Ensure the providers and native libraries were loaded from
             * this image's install locations, not look-alikes elsewhere */
            verifyProviderOrigin();

            /* Reject options that patch modules or extend the boot class path,
             * which can replace provider classes */
            verifyJvmOptions();

            /* Ensure wolfJCE reports a native wolfCrypt FIPS build of the
             * expected version, with passing self tests and no error state */
            verifyFipsModuleState();

            /* System CA certificates must be in WKS format */
            verifyCACertificatesAreWKSFormat();

            /* Run the FIPS Power-On Self Test (POST) */
            forceRunPOST();

            /* Check the providers listed in java.security */
            javaSecuritySanityChecks();

            /* Report non-FIPS service grants configured in java.security */
            printFilteredProviderGrants();

            /* Expected algorithms must come from wolfJCE and wolfJSSE */
            javaFIPSAlgorithmAvailabilityChecks();

            /* Algorithms outside the FIPS boundary must be unavailable */
            verifyUnavailableAlgorithms();

            /* List every service of every provider, verify each one is allowed
             * for its provider */
            verifyProviderServices();

            /* Strong SecureRandom, default SSLContext, TLS suites and EMS */
            additionalFIPSSecurityTests();

            /* Ensure the FIPS module did not enter an error state while
             * running the checks above */
            System.out.println(
                "\nVerifying wolfCrypt FIPS module status after checks...");
            verifyFipsModuleStatus();

        } catch (Exception e) {
            System.err.println("\nERROR: FIPS provider verification failed!");
            System.err.println("Exception: " + e.getClass().getName() + ": " +
                e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * List the registered security providers, marking SASL mechanisms that
     * are disabled or cannot be used.
     */
    public void listAllRegisteredSecurityProviders() {

        Provider[] providers = Security.getProviders();

        System.out.println("\nCurrently loaded security providers:");

        for (int i = 0; i < providers.length; i++) {
            Provider p = providers[i];
            String line = "\t" + (i + 1) + ". " + p.getName() + " v" +
                p.getVersion() + " - ";
            String info = p.getInfo().trim();
            int open = info.indexOf('(');

            if ((line + info).length() <= 80 || open <= 0 ||
                !info.endsWith(")")) {
                System.out.println(line + info);
            }
            else {
                System.out.println(line + info.substring(0, open).trim());
                for (String item : info.substring(open + 1,
                        info.length() - 1).split(";")) {
                    item = item.trim();
                    if (item.startsWith("implements ")) {
                        item = item.substring("implements ".length());
                    }
                    if (!item.isEmpty()) {
                        System.out.println("\t\t" + item);
                    }
                }
            }

            /* Mechanisms the info lists that are disabled or need an
             * algorithm outside the module */
            for (Map.Entry<String, String> n :
                    saslMechanismNotes(p).entrySet()) {
                System.out.println("\t\t" + n.getKey() + "   [" +
                    n.getValue() + "]");
            }
        }
    }

    /**
     * Confirm wolfJCE is registered at priority 1 and wolfJSSE at priority 2.
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
     * wolfSSL provider modules and the JAR each must be loaded from. The
     * image puts these JARs on the module path in JAVA_TOOL_OPTIONS.
     */
    private static final String[][] PROVIDER_MODULES = {
        /* { module name, JAR path } */
        { "com.wolfssl.wolfcrypt", "/usr/share/java/wolfcrypt-jni.jar" },
        { "com.wolfssl", "/usr/share/java/wolfssl-jsse.jar" },
        { "com.wolfssl.security.providers",
          "/usr/share/java/filtered-providers.jar" }
    };

    /** wolfSSL native libraries and the directory each must be loaded from. */
    private static final String[][] NATIVE_LIBRARIES = {
        /* { library file name, directory } */
        { "libwolfssl.so", "/usr/local/lib/" },
        { "libwolfcryptjni.so", "/usr/lib/jni/" },
        { "libwolfssljni.so", "/usr/lib/jni/" }
    };

    /**
     * Verify that the wolfSSL providers and the wolfCrypt Fips class come
     * from the provider JARs in /usr/share/java, and that the wolfSSL native
     * libraries come from /usr/local/lib and /usr/lib/jni. This detects
     * look-alike modules on an application's --module-path and look-alike
     * native libraries on a modified java.library.path.
     *
     * @throws SecurityException if a provider, module or native library is
     *         missing or was loaded from an unexpected location.
     * @throws IOException if a module location or /proc/self/maps cannot be
     *         read.
     */
    public void verifyProviderOrigin() throws SecurityException, IOException {

        System.out.println("\nVerifying wolfSSL provider and native " +
            "library locations...");

        Set<String> moduleNames = new HashSet<>();
        for (String[] pm : PROVIDER_MODULES) {
            moduleNames.add(pm[0]);
        }

        /* Each provider module must be resolved in the boot layer from its
         * JAR in /usr/share/java */
        for (String[] pm : PROVIDER_MODULES) {
            Optional<java.lang.module.ResolvedModule> rm =
                ModuleLayer.boot().configuration().findModule(pm[0]);
            if (!rm.isPresent()) {
                throw new SecurityException("ERROR: module " + pm[0] +
                    " is not loaded. The provider module path settings in " +
                    "JAVA_TOOL_OPTIONS may have been replaced.");
            }
            java.net.URI loc = rm.get().reference().location().orElse(null);
            if (loc == null || !"file".equals(loc.getScheme())) {
                throw new SecurityException("ERROR: module " + pm[0] +
                    " has an unexpected location: " + loc);
            }
            Path actual = Paths.get(loc).toRealPath();
            Path expected = Paths.get(pm[1]).toRealPath();
            if (!actual.equals(expected)) {
                throw new SecurityException("ERROR: module " + pm[0] +
                    " loaded from " + actual + ", expected " + expected);
            }
            System.out.println("\t" + pm[0] + ": " + actual);
        }

        /* Every registered wolfSSL provider, and the Fips class, must be
         * defined by one of those boot layer modules */
        List<Class<?>> classes = new ArrayList<>();
        for (Provider p : Security.getProviders()) {
            if (p.getClass().getName().startsWith("com.wolfssl.")) {
                classes.add(p.getClass());
            }
        }
        classes.add(com.wolfssl.wolfcrypt.Fips.class);
        for (Class<?> c : classes) {
            Module m = c.getModule();
            if (!m.isNamed() || !moduleNames.contains(m.getName()) ||
                m.getLayer() != ModuleLayer.boot()) {
                throw new SecurityException("ERROR: class " + c.getName() +
                    " is not loaded from a wolfSSL provider module " +
                    "(module: " + m + ")");
            }
        }
        if (Security.getProvider("wolfJCE").getClass().getModule() !=
                com.wolfssl.wolfcrypt.Fips.class.getModule()) {
            throw new SecurityException("ERROR: wolfJCE provider and the " +
                "wolfCrypt Fips class are in different modules");
        }
        System.out.println("\tProvider classes verified (" + classes.size() +
            " classes)");

        /* Native libraries: /proc/self/maps lists the real path of every
         * mapped shared library */
        List<String> maps = Files.readAllLines(Paths.get("/proc/self/maps"));
        for (String[] nl : NATIVE_LIBRARIES) {
            boolean found = false;
            for (String line : maps) {
                int idx = line.indexOf('/');
                if (idx < 0) {
                    continue;
                }
                String path = line.substring(idx);
                String name = path.substring(path.lastIndexOf('/') + 1);
                if (!name.equals(nl[0]) && !name.startsWith(nl[0] + ".") &&
                    !name.startsWith(nl[0] + " ")) {
                    continue;
                }
                found = true;
                if (!path.startsWith(nl[1])) {
                    throw new SecurityException("ERROR: native library " +
                        nl[0] + " loaded from " + path + ", expected " +
                        nl[1]);
                }
            }
            if (!found) {
                throw new SecurityException("ERROR: native library " + nl[0] +
                    " is not loaded");
            }
            System.out.println("\t" + nl[0] + ": " + nl[1]);
        }
    }

    /**
     * JVM options that can replace provider classes while the module and
     * library locations checked by verifyProviderOrigin() stay the same.
     */
    private static final String[] CLASS_PATCHING_OPTIONS = {
        "--patch-module", "--upgrade-module-path", "-Xbootclasspath/a"
    };

    /**
     * Fail if the JVM was started with options that can replace provider
     * classes. The JVM input arguments include options from JAVA_TOOL_OPTIONS,
     * JDK_JAVA_OPTIONS, JAVA_OPTS and argument files.
     *
     * @throws SecurityException if such an option is set.
     */
    private void verifyJvmOptions() throws SecurityException {

        System.out.println("\nVerifying JVM options...");

        List<String> bad = new ArrayList<>();
        for (String arg : java.lang.management.ManagementFactory
            .getRuntimeMXBean().getInputArguments()) {

            for (String opt : CLASS_PATCHING_OPTIONS) {
                if (arg.startsWith(opt)) {
                    bad.add(arg);
                }
            }
        }
        if (!bad.isEmpty()) {
            throw new SecurityException("ERROR: JVM options that can " +
                "replace provider classes are not allowed: " + bad);
        }

        System.out.println("\tNo module patching or boot class path options");
    }

    /**
     * Native wolfCrypt FIPS module version (Fips.fipsVersion, the native
     * HAVE_FIPS_VERSION) of wolfCrypt FIPS v5.2.3 (Certificate #5548).
     */
    private static final int EXPECTED_FIPS_VERSION = 5;

    /**
     * Verify the native wolfCrypt FIPS module state reported by wolfJCE
     * (com.wolfssl.wolfcrypt.Fips). Runs after verifyProviderOrigin(), which
     * checks that the Fips class comes from the installed wolfcrypt-jni.jar.
     *
     *     - Fips.enabled: the native wolfCrypt library is a FIPS build
     *     - Fips.fipsVersion: the module version is 5 (wolfCrypt FIPS
     *       v5.2.3)
     *     - Fips.runAllCast_fips(): all conditional algorithm self tests
     *       (CASTs) pass. wolfJCE already runs them when it loads, but ignores
     *       the result. A passing run is remembered, so this call repeats
     *       them only if that run failed.
     *     - Fips.wolfCrypt_GetStatus_fips(): the module is not in an error
     *       state
     *
     * @throws SecurityException if any of the above checks fail.
     */
    public void verifyFipsModuleState() throws SecurityException {

        System.out.println("\nVerifying wolfCrypt FIPS module state...");

        if (!com.wolfssl.wolfcrypt.Fips.enabled) {
            throw new SecurityException("ERROR: wolfJCE reports that the " +
                "native wolfCrypt library is not a FIPS build " +
                "(Fips.enabled is false)");
        }
        System.out.println("\tFips.enabled: true");

        int actual = com.wolfssl.wolfcrypt.Fips.fipsVersion;
        if (actual != EXPECTED_FIPS_VERSION) {
            throw new SecurityException("ERROR: native wolfCrypt FIPS " +
                "module version is " + actual + ", expected " +
                EXPECTED_FIPS_VERSION + " (wolfCrypt FIPS v5.2.3)");
        }
        System.out.println("\tFips.fipsVersion: " + actual +
            " (wolfCrypt FIPS v5.2.3)");

        int castFailures = com.wolfssl.wolfcrypt.Fips.runAllCast_fips();
        if (castFailures != 0) {
            throw new SecurityException("ERROR: wolfCrypt FIPS conditional " +
                "algorithm self tests failed (" + castFailures + " failed)");
        }
        System.out.println("\tFIPS conditional algorithm self tests passed");

        verifyFipsModuleStatus();
    }

    /**
     * Verify that the native wolfCrypt FIPS module is not in an error state
     * (wolfCrypt_GetStatus_fips() returns 0). Called by
     * verifyFipsModuleState(), and again after all other checks.
     *
     * @throws SecurityException if the module reports an error state.
     */
    public void verifyFipsModuleStatus() throws SecurityException {

        int status = com.wolfssl.wolfcrypt.Fips.wolfCrypt_GetStatus_fips();
        if (status != 0) {
            throw new SecurityException("ERROR: wolfCrypt FIPS module is " +
                "in an error state (wolfCrypt_GetStatus_fips returned " +
                status + ")");
        }
        System.out.println("\twolfCrypt_GetStatus_fips: 0 (no error)");
    }

    /**
     * Verify that the system CA certificates keystore (cacerts) is in WKS
     * (WolfSSLKeyStore) format. JKS and PKCS12 keystores come from Sun
     * providers, which do not use wolfCrypt FIPS. The image converts cacerts
     * at build time, so this is a sanity check.
     *
     * @throws SecurityException if cacerts is not in WKS format or cannot be
     *         loaded.
     */
    public void verifyCACertificatesAreWKSFormat() throws SecurityException {

        System.out.println("\nVerifying system CA certs are in WKS format...");

        String javaHome = System.getProperty("java.home");
        String cacertsPath = javaHome + "/lib/security/cacerts";

        System.out.println("\tChecking cacerts file: " + cacertsPath);

        try {
            KeyStore wksStore = KeyStore.getInstance("WKS");
            try (FileInputStream fis = new FileInputStream(cacertsPath)) {
                wksStore.load(fis, "changeitchangeit".toCharArray());
                int certCount = wksStore.size();
                System.out.println("\tSuccessfully loaded " + certCount +
                    " certificates from WKS format cacerts");
            }

        } catch (Exception wksException) {
            /* No provider in this image can load JKS or PKCS12, so name the
             * format from the file's first bytes instead */
            String format = keyStoreFileFormat(cacertsPath);
            throw new SecurityException("ERROR: Unable to load system " +
                "cacerts file as WKS" + (format == null ? "" :
                ": it is in " + format + " format, but must be WKS for " +
                "FIPS compliance. It may have been replaced, for example " +
                "by an upgrade of the zulu25 packages") +
                ". WKS error: " + wksException.getMessage());
        }

        System.out.println("\tSystem CA certificates verified as WKS format");
    }

    /**
     * Identify a non-WKS keystore file format from its first bytes.
     *
     * @param path keystore file path.
     * @return "JKS", "JCEKS" or "PKCS12", or null if the format is not
     *         recognized or the file cannot be read.
     */
    private static String keyStoreFileFormat(String path) {

        byte[] magic = new byte[4];

        try (FileInputStream fis = new FileInputStream(path)) {
            if (fis.readNBytes(magic, 0, 4) != 4) {
                return null;
            }
        } catch (IOException e) {
            return null;
        }

        int m = ((magic[0] & 0xff) << 24) | ((magic[1] & 0xff) << 16) |
            ((magic[2] & 0xff) << 8) | (magic[3] & 0xff);

        if (m == 0xFEEDFEED) {
            return "JKS";
        }
        if (m == 0xCECECECE) {
            return "JCEKS";
        }
        if (magic[0] == 0x30) {
            /* DER SEQUENCE: PKCS12, the stock JDK 18+ cacerts format */
            return "PKCS12";
        }

        return null;
    }

    /**
     * Run the wolfCrypt FIPS POST by hashing with a wolfJCE MessageDigest.
     *
     * @throws SecurityException if the POST fails.
     */
    public void forceRunPOST() throws SecurityException,
        NoSuchAlgorithmException {

        System.out.println("\nForcing FIPS POST via MessageDigest invocation");

        Provider wolfJCE = Security.getProvider("wolfJCE");
        MessageDigest md = MessageDigest.getInstance("SHA-256", wolfJCE);
        md.digest("FIPS POST test".getBytes());

        System.out.println("\tFIPS POST test completed successfully");
    }

    /**
     * Check the security providers listed in java.security: each must be a
     * known, allowed provider.
     *
     * @throws SecurityException if java.security lists a provider that is
     *         not allowed.
     * @throws IOException if java.security cannot be read.
     */
    public void javaSecuritySanityChecks()
        throws SecurityException, IOException {

        String javaHome = System.getProperty("java.home");
        Path securityFile = Paths.get(javaHome, "conf",
            "security", "java.security");

        System.out.println("\nRunning sanity checks on java.security");
        System.out.println("\tReading from: " + securityFile.toString());

        /* Collect the active and commented-out security.provider lines */
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

            /* Label known providers and flag violations */
            if (provider.contains("WolfSSL") ||
                provider.contains("WolfCrypt")) {
                status = "   [Expected / FIPS]";

            /* wolfSSL filtered wrappers around Sun providers */
            } else if (provider.equals(
                "com.wolfssl.security.providers.FilteredSun")) {
                status = "   [Expected / filtered Sun provider]";
            } else if (provider.equals(
                "com.wolfssl.security.providers.FilteredSunRsaSign")) {
                status = "   [Expected / filtered SunRsaSign provider]";
            } else if (provider.equals(
                "com.wolfssl.security.providers.FilteredSunEC")) {
                status = "   [Expected / filtered SunEC provider]";

            /* Providers that must not be present */
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
                status = "   [GSS-API/Kerberos, delegates to JCE]";
            } else if (provider.contains("SunSASL")) {
                status = "   [SASL, delegates to JCE]";
            } else if (provider.contains("XMLDSig")) {
                status = "   [XML Digital Signature, delegates to JCE]";
            } else if (provider.contains("JdkLDAP")) {
                status = "   [JDK LDAP, delegates to JSSE for LDAPS]";
            } else if (provider.contains("JdkSASL")) {
                status = "   [JDK SASL, delegates to JCE]";

            /* Anything else is unknown */
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
     * Check that the algorithms wolfJCE and wolfJSSE are expected to provide
     * come from those providers when getInstance() is called without a
     * provider name, so no other provider supplies one of them first.
     * Algorithms that must not be available are checked by
     * verifyUnavailableAlgorithms().
     *
     * @throws SecurityException if an algorithm cannot be created or comes
     *         from another provider.
     */
    public void javaFIPSAlgorithmAvailabilityChecks()
        throws SecurityException {

        int testCount = 0;
        int passCount = 0;

        System.out.println(
            "\nTesting wolfSSL algorithm class instantiation...");

        /* MessageDigest. MD5 is compiled out (--disable-md5) */
        String[] wolfJceDigests = {
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        };

        /* Mac */
        String[] wolfJceMacs = {
            "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384",
            "HmacSHA512", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384",
            "HmacSHA3-512", "AESCMAC", "AES-CMAC", "AESGMAC", "AES-GMAC"
        };

        /* Cipher. Padded RSA is left out because java.security disables it
         * (jdk.crypto.disabledAlgorithms) and a -D override can re-enable
         * it. */
        String[] wolfJceCiphers = {
            "AES/CBC/NoPadding", "AES/CBC/PKCS5Padding",
            "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding",
            "AES/CTR/NoPadding",
            "AES/OFB/NoPadding",
            "AES/GCM/NoPadding",
            "AES/CCM/NoPadding",
            "RSA/ECB/NoPadding"
        };

        /* Signature. SHA1withECDSA and SHA3-*withRSA are left out for the
         * same reason. */
        String[] wolfJceSignatures = {
            "SHA1withRSA",
            "SHA224withRSA",
            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "SHA224withECDSA",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA",
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

        /* SecretKeyFactory */
        String[] wolfJceSecretKeyFactories = {
            "PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224",
            "PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA384",
            "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA3-224",
            "PBKDF2WithHmacSHA3-256", "PBKDF2WithHmacSHA3-384",
            "PBKDF2WithHmacSHA3-512"
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

        /* MessageDigest */
        for (String alg : wolfJceDigests) {
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

        /* Mac */
        for (String alg : wolfJceMacs) {
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

        /* Cipher */
        for (String alg : wolfJceCiphers) {
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

        /* Signature */
        for (String alg : wolfJceSignatures) {
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

        /* SecretKeyFactory */
        for (String alg : wolfJceSecretKeyFactories) {
            testCount++;
            try {
                SecretKeyFactory skf = SecretKeyFactory.getInstance(alg);
                String providerName = skf.getProvider().getName();
                if ("wolfJCE".equals(providerName)) {
                    System.out.println("\tSecretKeyFactory: " + alg +
                        " -> " + providerName);
                    passCount++;
                } else {
                    throw new SecurityException("SecretKeyFactory: " + alg +
                        " using wrong provider: " + providerName +
                        " (expected wolfJCE)");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Failed to create SecretKeyFactory: " + alg + ": " +
                    e.getMessage());
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

        /* CertPathBuilder PKIX: wolfJCE (wolfSSL 5.9.2 and later) */
        testCount++;
        try {
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
            String providerName = cpb.getProvider().getName();
            if ("wolfJCE".equals(providerName)) {
                System.out.println("\tCertPathBuilder: PKIX -> " +
                    providerName);
                passCount++;
            } else {
                throw new SecurityException("CertPathBuilder: PKIX using " +
                    "wrong provider: " + providerName +
                    " (expected wolfJCE)");
            }
        } catch (Exception e) {
            throw new SecurityException(
                "Failed to create CertPathBuilder: PKIX: " + e.getMessage());
        }

        /* CertPathValidator PKIX: wolfJCE */
        testCount++;
        try {
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            String providerName = cpv.getProvider().getName();
            if ("wolfJCE".equals(providerName)) {
                System.out.println("\tCertPathValidator: PKIX -> " +
                    providerName);
                passCount++;
            } else {
                throw new SecurityException("CertPathValidator: PKIX using " +
                    "wrong provider: " + providerName + " (expected wolfJCE)");
            }
        } catch (Exception e) {
            throw new SecurityException(
                "Failed to create CertPathValidator: PKIX: " + e.getMessage());
        }

        /* KeyStore WKS: wolfJCE */
        testCount++;
        try {
            KeyStore ks = KeyStore.getInstance("WKS");
            String providerName = ks.getProvider().getName();
            if ("wolfJCE".equals(providerName)) {
                System.out.println("\tKeyStore: WKS -> " + providerName);
                passCount++;
            } else {
                throw new SecurityException("KeyStore: WKS using " +
                    "wrong provider: " + providerName + " (expected wolfJCE)");
            }
        } catch (Exception e) {
            throw new SecurityException(
                "Failed to create KeyStore: WKS: " + e.getMessage());
        }

        System.out.println("\n\tAlgorithm class instantiation results:");
        System.out.println("\t\tTests passed: " + passCount + "/" + testCount);

        if (passCount != testCount) {
            throw new SecurityException(
                "Algorithm class instantiation tests failed: " +
                (testCount - passCount) + " failures out of " + testCount +
                " tests");
        }

        System.out.println("\tAll expected algorithm classes " +
            "instantiated successfully with correct providers");
    }

    /**
     * Algorithms that must not be available with wolfCrypt FIPS v5.2.3
     * (Certificate #5548). Each row is { service type, algorithm, ... }.
     * This uses wolfJCE names (what wolfJCE would register if the native
     * library enabled the algorithm), plus the stock JDK names where they
     * differ.
     *
     * KeyStore JKS / PKCS12 are allowed from wolfJCE when java.security
     * enables wolfJCE's mapping of that type to WKS
     * (WOLFJCE_WKS_MAPPING_PROPERTIES).
     */
    private static final String[][] UNAVAILABLE_ALGORITHMS = {
        { "MessageDigest", "MD2", "MD4", "MD5", "SHAKE128-256",
          "SHAKE256-512" },
        { "Mac", "HmacMD5" },
        { "Signature", "MD5withRSA", "Ed25519", "Ed448", "EdDSA", "ML-DSA",
          "ML-DSA-65", "SLH-DSA", "LMS", "HSS/LMS", "XMSS" },
        { "Cipher", "DES/CBC/NoPadding", "DESede/CBC/NoPadding",
          "DESede/ECB/NoPadding", "RC2", "ARCFOUR", "ChaCha20",
          "ChaCha20-Poly1305", "PBEWithMD5AndDES",
          "PBEWithHmacSHA256AndAES_256", "AES/XTS/NoPadding",
          "AES/CFB/NoPadding", "AES/KW/PKCS5Padding", "AESWrap" },
        { "SecretKeyFactory", "DES", "DESede", "PBEWithMD5AndDES",
          "PBEWithHmacSHA256AndAES_256" },
        { "KeyAgreement", "X25519", "X448", "XDH" },
        { "KeyPairGenerator", "X25519", "X448", "XDH", "Ed25519", "Ed448",
          "EdDSA", "ML-DSA", "ML-KEM", "SLH-DSA" },
        { "KeyFactory", "X25519", "X448", "XDH", "Ed25519", "Ed448", "EdDSA",
          "ML-DSA", "ML-KEM", "SLH-DSA", "LMS", "XMSS" },
        { "AlgorithmParameters", "X25519", "X448" },
        { "KDF", "HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512" },
        { "KEM", "DHKEM", "ML-KEM", "ML-KEM-768" },
        { "KeyStore", "JKS", "PKCS12", "JCEKS", "DKS" }
    };

    /**
     * Return the provider that getInstance(algorithm) of a service type
     * returns, or null if that API reports the algorithm as not available
     * (NoSuchAlgorithmException, NoSuchPaddingException for Cipher, or a
     * KeyStoreException caused by NoSuchAlgorithmException for KeyStore).
     *
     * @param type JCA service type.
     * @param algorithm algorithm name.
     * @return name of the provider, or null if not available.
     * @throws SecurityException for any other exception, or an unknown type.
     */
    private static String availableFrom(String type, String algorithm)
        throws SecurityException {

        Provider p = null;
        String name = null;

        try {
            switch (type) {
                case "MessageDigest":
                    p = MessageDigest.getInstance(algorithm).getProvider();
                    break;
                case "Mac":
                    p = Mac.getInstance(algorithm).getProvider();
                    break;
                case "Cipher":
                    p = Cipher.getInstance(algorithm).getProvider();
                    break;
                case "Signature":
                    p = Signature.getInstance(algorithm).getProvider();
                    break;
                case "SecretKeyFactory":
                    p = SecretKeyFactory.getInstance(algorithm).getProvider();
                    break;
                case "KeyAgreement":
                    p = KeyAgreement.getInstance(algorithm).getProvider();
                    break;
                case "KeyPairGenerator":
                    p = KeyPairGenerator.getInstance(algorithm).getProvider();
                    break;
                case "KeyFactory":
                    p = KeyFactory.getInstance(algorithm).getProvider();
                    break;
                case "AlgorithmParameters":
                    p = AlgorithmParameters.getInstance(algorithm)
                        .getProvider();
                    break;
                case "AlgorithmParameterGenerator":
                    p = AlgorithmParameterGenerator.getInstance(algorithm)
                        .getProvider();
                    break;
                case "KDF":
                    name = KDF.getInstance(algorithm).getProviderName();
                    break;
                case "KEM":
                    /* KEM has no provider accessor, look it up */
                    KEM.getInstance(algorithm);
                    Provider[] kemProviders =
                        Security.getProviders("KEM." + algorithm);
                    name = (kemProviders != null) ?
                        kemProviders[0].getName() : "unknown provider";
                    break;
                case "KeyStore":
                    p = KeyStore.getInstance(algorithm).getProvider();
                    break;
                default:
                    throw new SecurityException("ERROR: unsupported " +
                        "service type in unavailable algorithm table: " + type);
            }

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return null;

        } catch (KeyStoreException e) {
            if (e.getCause() instanceof NoSuchAlgorithmException) {
                return null;
            }
            throw new SecurityException("ERROR: " + type + ": " + algorithm +
                ": unexpected exception: " + e, e);

        } catch (SecurityException e) {
            throw e;

        } catch (Exception e) {
            throw new SecurityException("ERROR: " + type + ": " + algorithm +
                ": unexpected exception: " + e, e);
        }

        return (p != null) ? p.getName() : name;
    }

    /**
     * If a filtered provider returned an algorithm because its
     * additionalServices property grants it, return that property name.
     * Matches the provider's canonical service name, not the alias or name
     * used in the table.
     *
     * @param providerName provider getInstance() returned.
     * @param type JCA service type.
     * @param algorithm algorithm name used with getInstance().
     * @return the granting property name, or null if not granted.
     */
    private static String grantingProperty(String providerName, String type,
        String algorithm) {

        Provider p = Security.getProvider(providerName);
        if (p == null) {
            return null;
        }

        String cls = p.getClass().getName();
        Provider.Service svc = p.getService(type, algorithm);
        if (svc == null || !grantedServices(cls).contains(
            serviceKey(svc.getType(), svc.getAlgorithm()))) {
            return null;
        }

        return FILTERED_PROVIDER_GRANT_PROPERTIES.get(cls);
    }

    /**
     * wolfJCE Security properties that register a KeyStore type as WKS
     * (WolfSSLKeyStore). wolfJCE enables each mapping when its property is
     * "true" (ignoring case). The mapped KeyStore is wolfJCE's WKS, so the
     * unavailable algorithm check allows that type from wolfJCE.
     */
    private static final Map<String, String> WOLFJCE_WKS_MAPPING_PROPERTIES =
        Map.of("JKS", "wolfjce.mapJKStoWKS",
               "PKCS12", "wolfjce.mapPKCS12toWKS");

    /**
     * If wolfJCE returned a KeyStore type because java.security maps that
     * type to WKS, return the mapping property name.
     *
     * @param providerName provider getInstance() returned.
     * @param type JCA service type.
     * @param algorithm algorithm name used with getInstance().
     * @return the mapping property name, or null if not mapped.
     */
    private static String wksMappingProperty(String providerName,
        String type, String algorithm) {

        if (!"KeyStore".equals(type) || !"wolfJCE".equals(providerName)) {
            return null;
        }

        String prop = WOLFJCE_WKS_MAPPING_PROPERTIES.get(algorithm);
        if (prop == null ||
            !"true".equalsIgnoreCase(Security.getProperty(prop))) {
            return null;
        }

        return prop;
    }

    /** Terminal width that wrapped lists stay within, counting tabs as 8. */
    private static final int OUTPUT_WIDTH = 80;

    /**
     * Print "label: a, b, c" indented by the given number of tabs, wrapped
     * at OUTPUT_WIDTH columns, with continuation lines aligned under the
     * first item.
     *
     * @param tabs number of leading tabs.
     * @param label text before the list, for example a service type.
     * @param items list items, printed comma-separated.
     */
    private static void printWrappedList(int tabs, String label,
        List<String> items) {

        String indent = "\t".repeat(tabs);
        int itemCol = (tabs * 8) + label.length() + 2;
        StringBuilder line = new StringBuilder(indent + label + ": ");
        int col = itemCol;

        for (int i = 0; i < items.size(); i++) {
            String item = items.get(i) + ((i < items.size() - 1) ? "," : "");
            boolean first = (col == itemCol);
            if (!first && (col + 1 + item.length() > OUTPUT_WIDTH)) {
                System.out.println(line);
                line.setLength(0);
                line.append(indent).append(" ".repeat(label.length() + 2));
                col = itemCol;
                first = true;
            }
            if (!first) {
                line.append(' ');
                col++;
            }
            line.append(item);
            col += item.length();
        }

        System.out.println(line);
    }

    /**
     * Verify that algorithms outside the wolfCrypt FIPS v5.2.3 boundary are
     * not available. getInstance() must throw the "not available" exception
     * its API documents, and any other exception fails the check. Since
     * verifyProviderServices() limits cryptography to wolfJCE and wolfJSSE,
     * this mainly catches wolfJCE registering an algorithm the native FIPS
     * build was not expected to enable.
     *
     * Two cases are allowed: an algorithm granted through a filtered
     * provider's additionalServices property (for example MessageDigest.MD5
     * through FilteredSun), from that provider, and KeyStore JKS / PKCS12
     * from wolfJCE when java.security maps the type to WKS
     * (wolfjce.mapJKStoWKS / wolfjce.mapPKCS12toWKS).
     *
     * @throws SecurityException if any listed algorithm is available, or
     *         getInstance() throws an unexpected exception.
     */
    public void verifyUnavailableAlgorithms() throws SecurityException {

        System.out.println("\nVerifying non-FIPS algorithms are unavailable");

        int checked = 0;
        int grantedCount = 0;
        int mappedCount = 0;
        int violations = 0;

        System.out.println("\tUnavailable algorithms:");
        for (String[] row : UNAVAILABLE_ALGORITHMS) {
            String type = row[0];
            List<String> unavailable = new ArrayList<>();
            for (int i = 1; i < row.length; i++) {
                checked++;
                String provider = availableFrom(type, row[i]);
                String grant = (provider == null) ? null :
                    grantingProperty(provider, type, row[i]);
                String mapping = (provider == null) ? null :
                    wksMappingProperty(provider, type, row[i]);
                if (provider == null) {
                    unavailable.add(row[i]);
                }
                else if (grant != null) {
                    System.out.println("\t\t" + type + ": " + row[i] +
                        " -> " + provider + "   [granted by " + grant +
                        "]");
                    grantedCount++;
                }
                else if (mapping != null) {
                    System.out.println("\t\t" + type + ": " + row[i] +
                        " -> " + provider + "   [mapped to WKS by " +
                        mapping + "]");
                    mappedCount++;
                }
                else {
                    System.out.println("\t\t" + type + ": " + row[i] +
                        " -> " + provider +
                        "   >> SHOULD NOT BE AVAILABLE");
                    violations++;
                }
            }
            if (!unavailable.isEmpty()) {
                printWrappedList(2, type, unavailable);
            }
        }

        System.out.println("\tUnavailable algorithm results:");
        System.out.println("\t\tAlgorithms checked: " + checked);
        System.out.println("\t\tGranted (additionalServices): " + grantedCount);
        System.out.println("\t\tMapped to WKS (wolfjce.map*toWKS): " +
            mappedCount);
        System.out.println("\t\tViolations found: " + violations);

        if (violations > 0) {
            throw new SecurityException("Found " + violations +
                " algorithms that should not be available (see the lines " +
                "marked >> above)");
        }

        System.out.println("\tAll listed non-FIPS algorithms are unavailable");
    }

    /** wolfJCE provider class. */
    private static final String WOLFJCE_PROVIDER_CLASS =
        "com.wolfssl.provider.jce.WolfCryptProvider";

    /** wolfJSSE provider class. */
    private static final String WOLFJSSE_PROVIDER_CLASS =
        "com.wolfssl.provider.jsse.WolfSSLProvider";

    /**
     * Filtered Sun provider classes and the exact services ("Type.Algorithm")
     * each one offers. Every listed service must be present. No other service
     * is allowed unless java.security grants it through the provider's
     * additionalServices property (FILTERED_PROVIDER_GRANT_PROPERTIES).
     */
    private static final Map<String, Set<String>> FILTERED_PROVIDER_SERVICES =
        Map.of(
            "com.wolfssl.security.providers.FilteredSun", Set.of(
                "CertificateFactory.X.509",
                "CertStore.Collection",
                "CertStore.com.sun.security.IndexedCollection",
                "Configuration.JavaLoginConfig"),
            "com.wolfssl.security.providers.FilteredSunEC", Set.of(
                "AlgorithmParameters.EC"),
            "com.wolfssl.security.providers.FilteredSunRsaSign", Set.of(
                "KeyFactory.RSASSA-PSS"));

    /**
     * Security property, per filtered provider class, that grants extra Sun
     * services, for example
     * wolfssl.filtered.sun.additionalServices=MessageDigest.MD5. Granted
     * services are Sun implementations outside the wolfCrypt FIPS boundary.
     */
    private static final Map<String, String>
        FILTERED_PROVIDER_GRANT_PROPERTIES = Map.of(
            "com.wolfssl.security.providers.FilteredSun",
                "wolfssl.filtered.sun.additionalServices",
            "com.wolfssl.security.providers.FilteredSunEC",
                "wolfssl.filtered.sunec.additionalServices",
            "com.wolfssl.security.providers.FilteredSunRsaSign",
                "wolfssl.filtered.sunrsasign.additionalServices");

    /**
     * Return the services a filtered provider class grants through its
     * additionalServices Security property, as lowercase "type.algorithm"
     * keys. Parses entries the same way the filtered providers do
     * (wolfcrypt-jni ProviderServiceCopier): comma-separated Type.Algorithm,
     * split at the first dot, both parts trimmed and non-empty, matched
     * case-insensitively against canonical service names.
     *
     * @param providerClass provider class name.
     * @return granted service keys, empty if none or not a filtered provider.
     */
    private static Set<String> grantedServices(String providerClass) {

        Set<String> keys = new HashSet<>();
        String prop = FILTERED_PROVIDER_GRANT_PROPERTIES.get(providerClass);
        String value = (prop == null) ? null : Security.getProperty(prop);
        if (value == null) {
            return keys;
        }

        for (String raw : value.split(",")) {
            String entry = raw.trim();
            int dot = entry.indexOf('.');
            if (dot <= 0 || dot == entry.length() - 1) {
                continue;
            }
            String type = entry.substring(0, dot).trim();
            String algo = entry.substring(dot + 1).trim();
            if (!type.isEmpty() && !algo.isEmpty()) {
                keys.add(serviceKey(type, algo));
            }
        }

        return keys;
    }

    /**
     * Lowercase "type.algorithm" key used to match grants.
     */
    private static String serviceKey(String type, String algorithm) {
        return (type + "." + algorithm).toLowerCase(Locale.ROOT);
    }

    /**
     * Print the filtered provider grants (additionalServices properties) set
     * in java.security. The provider service and unavailable algorithm checks
     * allow granted services, from the granting provider only, and mark them
     * in their output.
     */
    public void printFilteredProviderGrants() {

        System.out.println("\nFiltered provider grants (additionalServices " +
            "in java.security):");

        boolean any = false;
        for (String prop :
                new TreeSet<>(FILTERED_PROVIDER_GRANT_PROPERTIES.values())) {
            String value = Security.getProperty(prop);
            if (value != null && !value.trim().isEmpty()) {
                System.out.println("\t" + prop + "=" + value);
                any = true;
            }
        }

        if (!any) {
            System.out.println("\tNone");
        }
        else {
            System.out.println("\tWARNING: granted services are Sun " +
                "implementations, outside the wolfCrypt FIPS boundary, and " +
                "are not FIPS validated.");
            System.out.println("\tUsing them may invalidate FIPS 140-3 " +
                "compliance unless an approved exception covers that use.");
            System.out.println("\tThe startup checks allow them because " +
                "java.security grants them.");
        }
    }

    /**
     * JDK provider classes that do no cryptography themselves (they get it
     * from the JCA providers above), and the service types each one may offer,
     * with any algorithm.
     */
    private static final Map<String, Set<String>>
        DELEGATING_PROVIDER_SERVICE_TYPES = Map.of(
            /* SunJGSS */
            "sun.security.jgss.SunProvider", Set.of("GssApiMechanism"),
            /* SunSASL */
            "com.sun.security.sasl.Provider",
                Set.of("SaslClientFactory", "SaslServerFactory"),
            /* JdkSASL */
            "com.sun.security.sasl.gsskerb.JdkSASL",
                Set.of("SaslClientFactory", "SaslServerFactory"),
            /* XMLDSig */
            "org.jcp.xml.dsig.internal.dom.XMLDSigRI",
                Set.of("XMLSignatureFactory", "KeyInfoFactory",
                    "TransformService"),
            /* JdkLDAP (CertStore.LDAP) */
            "sun.security.provider.certpath.ldap.JdkLDAP",
                Set.of("CertStore"));

    /**
     * SASL mechanisms that need an algorithm outside the module, and the
     * service type and name of that algorithm.
     */
    private static final Map<String, String[]> SASL_MECHANISM_ALGORITHMS =
        Map.of(
            "CRAM-MD5", new String[] { "MessageDigest", "MD5" },
            "DIGEST-MD5", new String[] { "MessageDigest", "MD5" },
            "NTLM", new String[] { "SecretKeyFactory", "DES" });

    /**
     * Return a note for a SASL factory service whose mechanism is disabled by
     * jdk.sasl.disabledMechanisms or needs an algorithm outside the module.
     * The JDK still lists these mechanisms, so the note says whether one can
     * be used.
     *
     * @param type service type.
     * @param mechanism SASL mechanism (the service algorithm).
     * @return the note, or null for other services and mechanisms.
     */
    private static String saslMechanismNote(String type, String mechanism) {

        if (!type.equals("SaslClientFactory") &&
            !type.equals("SaslServerFactory")) {
            return null;
        }

        /* Split as javax.security.sasl.Sasl does, case-sensitive */
        String disabled = Security.getProperty("jdk.sasl.disabledMechanisms");
        if (disabled != null &&
            Arrays.asList(disabled.split("\\s*,\\s*")).contains(mechanism)) {
            return "disabled by jdk.sasl.disabledMechanisms";
        }

        String[] alg = SASL_MECHANISM_ALGORITHMS.get(mechanism);
        if (alg == null) {
            return null;
        }
        String provider = availableFrom(alg[0], alg[1]);
        if (provider == null) {
            return "needs " + alg[1] + ", not available";
        }
        return "uses " + alg[1] +
            (grantingProperty(provider, alg[0], alg[1]) != null ?
                " granted to " : " from ") + provider;
    }

    /**
     * Return the saslMechanismNote() notes for a provider's SASL services,
     * by mechanism.
     *
     * @param p provider.
     * @return notes by mechanism, sorted, empty if none.
     */
    private static Map<String, String> saslMechanismNotes(Provider p) {
        Map<String, String> notes = new TreeMap<>();
        for (Provider.Service s : p.getServices()) {
            String note = saslMechanismNote(s.getType(), s.getAlgorithm());
            if (note != null) {
                notes.put(s.getAlgorithm(), note);
            }
        }
        return notes;
    }

    /**
     * List every service of every registered provider, and verify each one
     * is allowed for that provider. Providers are identified by class, not by
     * the name they report.
     *
     *     - wolfJCE and wolfJSSE may offer any service. The services they
     *       must offer are checked by javaFIPSAlgorithmAvailabilityChecks().
     *     - FilteredSun, FilteredSunEC and FilteredSunRsaSign must offer
     *       exactly the services in FILTERED_PROVIDER_SERVICES, and must be
     *       registered. Services their additionalServices property grants
     *       are also allowed, and marked as granted.
     *     - The JDK delegating providers (SunJGSS, SunSASL, JdkSASL, XMLDSig,
     *       JdkLDAP) may offer only their service types.
     *     - Any other provider, and any other service, fails.
     *
     * Every service is checked, not only the one getInstance() returns first,
     * so an ungranted second copy of a service that is reachable by naming
     * its provider (for example getInstance("SHA-256", "FilteredSun")) also
     * fails.
     *
     * @throws SecurityException if any provider or service is not allowed,
     *         or a required provider or service is missing.
     */
    public void verifyProviderServices() throws SecurityException {

        System.out.println("\nVerifying security provider services...");

        Provider[] providers = Security.getProviders();
        Set<String> seenClasses = new HashSet<>();
        int totalServices = 0;
        int grantedCount = 0;
        int violations = 0;

        for (int i = 0; i < providers.length; i++) {

            Provider p = providers[i];
            String cls = p.getClass().getName();
            seenClasses.add(cls);

            boolean unrestricted = WOLFJCE_PROVIDER_CLASS.equals(cls) ||
                WOLFJSSE_PROVIDER_CLASS.equals(cls);
            Set<String> exact = FILTERED_PROVIDER_SERVICES.get(cls);
            Set<String> types = DELEGATING_PROVIDER_SERVICE_TYPES.get(cls);
            Set<String> granted = grantedServices(cls);

            String rule;
            if (unrestricted) {
                rule = "any service";
            }
            else if (exact != null) {
                rule = "listed services only, all required" +
                    (granted.isEmpty() ? "" : ", plus granted services");
            }
            else if (types != null) {
                rule = "service types " + new TreeSet<>(types);
            }
            else {
                rule = ">> UNKNOWN PROVIDER, not allowed";
                violations++;
            }

            System.out.println("\t" + (i + 1) + ". " + p.getName() + " (" +
                cls + "): " + rule);

            /* "Type.Algorithm" -> type, sorted */
            Map<String, String> services = new TreeMap<>();
            for (Provider.Service s : p.getServices()) {
                services.put(s.getType() + "." + s.getAlgorithm(), s.getType());
            }
            totalServices += services.size();

            for (Map.Entry<String, String> e : services.entrySet()) {
                boolean allowed = unrestricted ||
                    (exact != null && exact.contains(e.getKey())) ||
                    (types != null && types.contains(e.getValue()));
                if (allowed) {
                    String note = saslMechanismNote(e.getValue(),
                        e.getKey().substring(e.getValue().length() + 1));
                    System.out.println("\t\t" + e.getKey() +
                        (note != null ? "   [" + note + "]" : ""));
                }
                else if (exact != null && granted.contains(
                        e.getKey().toLowerCase(Locale.ROOT))) {
                    System.out.println("\t\t" + e.getKey() +
                        "   [granted by " +
                        FILTERED_PROVIDER_GRANT_PROPERTIES.get(cls) + "]");
                    grantedCount++;
                }
                else {
                    System.out.println("\t\t" + e.getKey() +
                        "   >> NOT ALLOWED");
                    violations++;
                }
            }

            /* Every listed filtered provider service is required */
            if (exact != null) {
                for (String r : new TreeSet<>(exact)) {
                    if (!services.containsKey(r)) {
                        System.out.println("\t\t" + r +
                            "   >> MISSING (required)");
                        violations++;
                    }
                }
            }
        }

        /* Filtered providers must be registered. wolfJCE and wolfJSSE are
         * checked by confirmWolfSSLProvidersAreRegistered(). */
        for (String cls : new TreeSet<>(FILTERED_PROVIDER_SERVICES.keySet())) {
            if (!seenClasses.contains(cls)) {
                System.out.println("\t" + cls +
                    "   >> MISSING (required provider)");
                violations++;
            }
        }

        System.out.println("\tProvider service verification results:");
        System.out.println("\t\tProviders checked: " + providers.length);
        System.out.println("\t\tServices checked: " + totalServices);
        System.out.println("\t\tGranted (additionalServices): " +
            grantedCount);
        System.out.println("\t\tViolations found: " + violations);

        if (violations > 0) {
            throw new SecurityException("Found " + violations +
                " provider service violations (see lines marked >> above)");
        }

        System.out.println("\tAll provider services verified");
    }

    /**
     * Additional checks:
     * 1. SecureRandom.getInstanceStrong() comes from a wolfSSL provider
     * 2. SSLContext.getDefault() comes from a wolfSSL provider
     * 3. The default SSLContext's TLS protocols and cipher suites
     * 4. The TLS 1.2 Extended Master Secret requirement can be enforced
     *
     * @throws SecurityException if any check fails
     */
    public void additionalFIPSSecurityTests() throws SecurityException {

        System.out.println(
            "\nRunning additional FIPS security compliance tests...");

        testSecureRandomStrongUsesWolfSSL();
        testSSLContextDefaultUsesWolfSSL();
        testTlsProtocolsAndCipherSuites();
        testTlsExtendedMasterSecret();

        System.out.println("\tAll additional FIPS security tests passed");
    }

    /**
     * Check that SecureRandom.getInstanceStrong() comes from a wolfSSL
     * provider.
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
     * Check that SSLContext.getDefault() comes from a wolfSSL provider.
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
     * Cipher suite name parts for ciphers and MACs that are not in the
     * wolfCrypt FIPS module, matched against the parts of a suite name split
     * at '_'. Other suites (static key exchange, NULL or anonymous) use only
     * module cryptography, and the native wolfSSL build decides whether they
     * exist.
     */
    private static final Set<String> DISALLOWED_SUITE_PARTS = Set.of(
        "RC4", "RC2", "DES", "DES40", "3DES", "IDEA", "MD5", "CHACHA20",
        "POLY1305", "CAMELLIA", "ARIA", "SEED", "SM4", "SM3");

    /**
     * Return the DISALLOWED_SUITE_PARTS part in a cipher suite name, or null
     * if the suite is allowed.
     *
     * @param suite cipher suite name.
     * @return the disallowed name part, or null.
     */
    private static String disallowedSuiteReason(String suite) {

        for (String part : suite.split("_")) {
            if (DISALLOWED_SUITE_PARTS.contains(part)) {
                return part;
            }
        }

        return null;
    }

    /**
     * List the default SSLContext's enabled (default) and supported TLS
     * protocols, for information. The TLS protocol is outside the FIPS
     * module, and java.security (jdk.tls.disabledAlgorithms) and the native
     * wolfSSL build decide which versions are available.
     *
     * Then check that no enabled or supported cipher suite uses a cipher or
     * MAC outside the wolfCrypt FIPS module (disallowedSuiteReason()). This
     * verifies the native wolfSSL build and restricts nothing itself.
     *
     * @throws SecurityException if a cipher suite is not allowed.
     */
    private void testTlsProtocolsAndCipherSuites()
        throws SecurityException {

        SSLParameters enabled;
        SSLParameters supported;

        try {
            SSLContext ctx = SSLContext.getDefault();
            enabled = ctx.getDefaultSSLParameters();
            supported = ctx.getSupportedSSLParameters();

        } catch (Exception e) {
            throw new SecurityException("Failed to get default SSLContext " +
                "parameters: " + e.getMessage(), e);
        }

        int violations = 0;

        System.out.println("\tTLS protocols (default): " +
            String.join(", ", enabled.getProtocols()));
        System.out.println("\tTLS protocols (supported): " +
            String.join(", ", supported.getProtocols()));

        List<String> enabledSuites = Arrays.asList(enabled.getCipherSuites());
        List<String> supportedOnly = new ArrayList<>(
            Arrays.asList(supported.getCipherSuites()));
        supportedOnly.removeAll(enabledSuites);

        Map<String, List<String>> suites = new LinkedHashMap<>();
        suites.put("default", enabledSuites);
        suites.put("supported, not enabled by default", supportedOnly);
        for (Map.Entry<String, List<String>> set : suites.entrySet()) {
            System.out.println("\tTLS cipher suites (" + set.getKey() + "): " +
                (set.getValue().isEmpty() ? "None" : set.getValue().size()));
            for (String suite : set.getValue()) {
                String reason = disallowedSuiteReason(suite);
                System.out.println("\t\t" + suite + (reason == null ? "" :
                    "   >> NOT ALLOWED (" + reason + ")"));
                violations += (reason == null) ? 0 : 1;
            }
        }

        if (violations > 0) {
            throw new SecurityException("Found " + violations + " TLS " +
                "cipher suites that are not allowed (see the lines marked " +
                ">> above)");
        }
    }

    /**
     * Report whether TLS 1.2 requires the Extended Master Secret (RFC 7627),
     * set by the jdk.tls.allowLegacyMasterSecret System property (false in
     * the image's JAVA_TOOL_OPTIONS). When required, confirm it can be
     * enforced. wolfJSSE ignores the property without
     * WolfSSLSession.requireExtendedMasterSecret(), and native wolfSSL needs
     * 5.9.4 or later.
     *
     * @throws SecurityException if EMS is required but cannot be enforced,
     *         or jdk.tls.allowLegacyMasterSecret is not "true" or "false".
     */
    private void testTlsExtendedMasterSecret() throws SecurityException {

        String useEMS = System.getProperty("jdk.tls.useExtendedMasterSecret");
        String allowLegacy =
            System.getProperty("jdk.tls.allowLegacyMasterSecret");

        /* wolfJSSE fails handshakes on values other than true/false */
        if (allowLegacy != null && !"true".equalsIgnoreCase(allowLegacy) &&
            !"false".equalsIgnoreCase(allowLegacy)) {
            throw new SecurityException("jdk.tls.allowLegacyMasterSecret " +
                "must be 'true' or 'false', not '" + allowLegacy + "'");
        }

        if ("false".equalsIgnoreCase(useEMS)) {
            System.out.println("\tTLS 1.2 Extended Master Secret: disabled " +
                "(jdk.tls.useExtendedMasterSecret=false)");
            return;
        }
        if (!"false".equalsIgnoreCase(allowLegacy)) {
            System.out.println("\tTLS 1.2 Extended Master Secret: not " +
                "required (jdk.tls.allowLegacyMasterSecret" +
                (allowLegacy == null ? " unset" : "=" + allowLegacy) + ")");
            return;
        }

        try {
            com.wolfssl.WolfSSLSession.class.getMethod(
                "requireExtendedMasterSecret");
        } catch (NoSuchMethodException e) {
            throw new SecurityException("jdk.tls.allowLegacyMasterSecret=" +
                "false is set, but this wolfJSSE does not support it, so " +
                "TLS 1.2 could use a legacy master secret");
        }

        long nativeVer = com.wolfssl.WolfSSL.getLibVersionHex();
        if (nativeVer < 0x05009004L) {
            throw new SecurityException("jdk.tls.allowLegacyMasterSecret=" +
                "false is set, but native wolfSSL 0x" +
                Long.toHexString(nativeVer) + " cannot require the Extended " +
                "Master Secret (needs 5.9.4 or later)");
        }

        System.out.println("\tTLS 1.2 Extended Master Secret: required " +
            "(jdk.tls.allowLegacyMasterSecret=false)");
    }
}
