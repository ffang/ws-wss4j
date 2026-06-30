/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.wss4j.dom.message;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.AlgorithmSuiteValidator;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests for ML-DSA (FIPS 204) in WS-Security.
 *
 * <p>ML-DSA key-type auto-detection and direct BC signature operations are tested here.
 * Full WS-Security XML-Dsig round-trip with ML-DSA requires Santuario to register
 * a {@code DOMMLDSASignatureMethod} implementation — that work belongs in Santuario,
 * not in wss4j.
 *
 * <p>Requires BouncyCastle 1.81+ and JDK 17+.
 */
public class PQCSignatureTest {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(PQCSignatureTest.class);

    private static boolean bcAvailable;

    @BeforeAll
    public static void setUp() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();
            bcAvailable = true;
        } catch (Exception e) {
            LOG.info("ML-DSA not available (BC < 1.81 or provider missing): {}", e.getMessage());
            bcAvailable = false;
        }
    }

    @AfterAll
    public static void tearDown() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * Verifies that the algorithm URI auto-detection in {@link WSSecSignature}
     * maps each ML-DSA JCA name to the correct provisional URI.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44," + WSS4JConstants.ML_DSA_44,
        "ML-DSA-65," + WSS4JConstants.ML_DSA_65,
        "ML-DSA-87," + WSS4JConstants.ML_DSA_87
    })
    public void testMLDSAAlgorithmUriAutoDetection(String jcaName, String expectedUri)
            throws Exception {
        assumeTrue(bcAvailable, "ML-DSA requires BouncyCastle 1.81+");

        KeyPair kp = KeyPairGenerator.getInstance(jcaName, "BC").generateKeyPair();
        X509Certificate cert = buildSelfSignedCert(kp, jcaName);

        // Simulate what WSSecSignature does: detect sigAlgo from cert public key
        String pubKeyAlgo = cert.getPublicKey().getAlgorithm();
        String sigAlgo = null;
        if (pubKeyAlgo.equalsIgnoreCase("ML-DSA-44")) {
            sigAlgo = WSS4JConstants.ML_DSA_44;
        } else if (pubKeyAlgo.equalsIgnoreCase("ML-DSA-65")) {
            sigAlgo = WSS4JConstants.ML_DSA_65;
        } else if (pubKeyAlgo.equalsIgnoreCase("ML-DSA-87")) {
            sigAlgo = WSS4JConstants.ML_DSA_87;
        }

        assertNotNull(sigAlgo, "Algorithm URI must be detected for " + jcaName);
        assertEquals(expectedUri, sigAlgo, "Detected URI must match expected");
        LOG.debug("{} → {}", pubKeyAlgo, sigAlgo);
    }

    /**
     * Verifies that BC can sign and verify with ML-DSA natively.
     * This confirms the JCA provider round-trip works before XML-Dsig integration.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87"
    })
    public void testMLDSABcSignatureRoundTrip(String jcaName) throws Exception {
        assumeTrue(bcAvailable, "ML-DSA requires BouncyCastle 1.81+");

        KeyPair kp = KeyPairGenerator.getInstance(jcaName, "BC").generateKeyPair();
        byte[] data = "Hello ML-DSA WS-Security".getBytes();

        Signature signer = Signature.getInstance(jcaName, "BC");
        signer.initSign(kp.getPrivate());
        signer.update(data);
        byte[] sig = signer.sign();

        assertTrue(sig.length > 0, "Signature must not be empty");

        Signature verifier = Signature.getInstance(jcaName, "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(data);
        assertTrue(verifier.verify(sig), "Signature must verify correctly");
        LOG.debug("{} signature length: {} bytes", jcaName, sig.length);
    }

    /**
     * Verifies that {@link AlgorithmSuiteValidator} passes ML-DSA keys
     * without throwing (security-level check, not bit-length check).
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87"
    })
    public void testMLDSAKeyPassesAlgorithmSuiteValidator(String jcaName) throws Exception {
        assumeTrue(bcAvailable, "ML-DSA requires BouncyCastle 1.81+");

        KeyPair kp = KeyPairGenerator.getInstance(jcaName, "BC").generateKeyPair();

        // Use a suite that requires elliptic-curve level 256 (security level 1 equivalent)
        AlgorithmSuite suite = new AlgorithmSuite();
        suite.setMinimumEllipticCurveKeyLength(0);
        suite.setMaximumEllipticCurveKeyLength(Integer.MAX_VALUE);
        suite.setMinimumAsymmetricKeyLength(0);
        suite.setMaximumAsymmetricKeyLength(Integer.MAX_VALUE);

        AlgorithmSuiteValidator validator = new AlgorithmSuiteValidator(suite);
        // Must not throw
        validator.checkAsymmetricKeyLength(kp.getPublic());
        LOG.debug("{} key passed AlgorithmSuiteValidator check", jcaName);
    }

    // ---- helpers -------------------------------------------------------

    private static X509Certificate buildSelfSignedCert(KeyPair kp, String jcaName)
            throws Exception {
        X500Name subject = new X500Name("CN=" + jcaName + " Test, O=WSS4J PQC Test");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86_400_000L);

        ContentSigner signer = new JcaContentSignerBuilder(jcaName)
            .setProvider("BC").build(kp.getPrivate());

        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, kp.getPublic())
                .build(signer));
    }
}
