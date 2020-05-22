/**
 * LE4j - ACME client for obtaining lets encrypt certificates as keystore.
 *
 * This project is using acme4j: http://acme4j.shredzone.org
 *
 * Copyright 2020 - Rony "ChillUpX" Tesch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.chillupx.le4j;

import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

@Slf4j
@RequiredArgsConstructor
public class LE4j {

    private static final String ACME_LETSENCRYPT_STAGING = "acme://letsencrypt.org/staging";
    private static final String ACME_LETSENCRYPT = "acme://letsencrypt.org";

    @Builder.Default private final int keySize = 2048;
    @Builder.Default private final boolean useStaging = false;
    @Builder.Default private final boolean writeCsrToFile = false;
    @Builder.Default private final long timeBetweenRetry = 3000;
    @Builder.Default private final String keystorePassword = "secure";
    private final String domain;
    private final String organisation;
    private final String accountKeyPath;
    private final String domainKeyPath;
    private final String domainCertPath;
    private final String domainKeystorePath;

    /**
     * This method creates a lets encrypt signed certificate and a corresponding keystore.
     *
     * For authentication LE4j will start a temporary webserver at port 80 for responding to
     * the Http01Challenge.
     *
     * The certificate and the keystore will be saved at domainCertPath and domainKeystorePath.
     *
     * Account and domain key pairs will be saved at accountKeyPath and domainKeyPath.
     *
     * @throws Exception If the proccess failes several exceptions can be throw. All should
     * contain an explaining message so you know what went wrong.
     */
    public void optainCert() throws Exception {
        // Setup account
        Account account = setupAccount();

        // Create Order
        Order order = account.newOrder().domains(domain).create();

        // Authorize Order
        authorizeOrder(order);

        KeyPair domainKeyPair = executeOrder(order);

        writeCertificate(order, domainKeyPair);
    }

    /**
     * This method writes the plain certificate and a corresponding keystore to disk.
     *
     * @param order The order to take certificate from
     * @param domainKeyPair The domain key pair to put into the keystore
     * @throws Exception
     */
    private void writeCertificate(Order order, KeyPair domainKeyPair) throws Exception {
        // Get certificate
        Certificate cert = order.getCertificate();

        // Write certificate
        try(FileWriter fw = new FileWriter(new File(domainCertPath, domain+".crt"))) {
            cert.writeCertificate(fw);
        }

        // Create empty keystore
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(null, null);
        ks.setKeyEntry(
                "key1",
                domainKeyPair.getPrivate(),
                keystorePassword.toCharArray(),
                cert.getCertificateChain().toArray(new X509Certificate[]{})
        );
        // Write keystore
        ks.store(new FileOutputStream(new File(domainKeystorePath, domain+".p12")), keystorePassword.toCharArray());
    }

    /**
     * This method executes a order. Therefore the domain key pair is generated
     * and the CSR ist sent.
     *
     * @param order The order to be processed
     * @return KeyPair - The domain key pair that is requested to get signed
     * @throws Exception
     */
    private KeyPair executeOrder(Order order) throws Exception {
        // Create Domain Key Pair
        File file = new File(domainKeyPath, domain+".key");
        KeyPair domainKeyPair = buildKeyPair(file);

        // Create signing request
        byte[] csr = generateCsr(domainKeyPair);

        // Run signing request
        order.execute(csr);

        // Wait for request to complete
        int times = 0;
        while(order.getStatus() != Status.VALID) {
            if(times >= 10) {
                throw new AcmeException("Order could not be executed...");
            }

            Thread.sleep(timeBetweenRetry);
            order.update();
            times++;
        }

        return domainKeyPair;
    }

    /**
     * This method prepares a CSR request.
     *
     * If writeCsrToFile is true the csr data will get written into a file at domainKeyPath.
     *
     * @param domainKeyPair domain key pair that should get signed
     * @return byte[] - Byte array of CSR request
     * @throws IOException
     */
    private byte[] generateCsr(KeyPair domainKeyPair) throws IOException {
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomain(domain);
        csrb.setOrganization(organisation);
        csrb.sign(domainKeyPair);

        if(writeCsrToFile) {
            csrb.write(new FileWriter(new File(domainKeyPath, domain+".csr")));
        }
        return csrb.getEncoded();
    }

    /**
     * This method loops through order authorizations and fullfills them.
     * @param order The order to process
     */
    private void authorizeOrder(Order order) throws Exception {
        for(Authorization auth : order.getAuthorizations()) {
            if(auth.getStatus() != Status.VALID) {
                Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
                if(challenge == null) {
                    throw new AcmeException("LE4j only supports Http01Challenge");
                }

                HttpChallengeSolver.builder()
                        .auth(auth)
                        .challenge(challenge)
                        .domain(domain)
                        .timeBetweenRetry(timeBetweenRetry)
                        .build()
                    .solve();
            }
        }
    }

    /**
     * This method either creates an new account with a new account.key file at the given accountKeyPath or
     * uses an existing account.key file at the given accountKeyPath for an existing account.
     *
     * @return Account - ACME Account
     * @throws Exception
     */
    private Account setupAccount() throws Exception {
        // Create account key pair
        File file = new File(accountKeyPath, "account.key");
        boolean accountExists = file.exists();
        KeyPair accountKeyPair = buildKeyPair(file);

        // Setup session
        Session session = new Session(useStaging ? ACME_LETSENCRYPT_STAGING : ACME_LETSENCRYPT);
        // Setup account
        AccountBuilder accountBuilder = new AccountBuilder()
                .useKeyPair(accountKeyPair)
                .agreeToTermsOfService();
        if(accountExists) {
            accountBuilder.onlyExisting();
        }
        // Create account
        return accountBuilder.create(session);
    }

    /**
     * This method reads a existing key file or creates a new one at the given location.
     * As key size the value of keySize is used.
     *
     * @param keyPairFile Where the key will be read/wrote
     * @return KeyPair - The read or newly created key pair
     * @throws IOException
     */
    private KeyPair buildKeyPair(File keyPairFile) throws IOException {
        if(!keyPairFile.exists()) {
            KeyPair keyPair = KeyPairUtils.createKeyPair(keySize);
            try(FileWriter fw = new FileWriter(keyPairFile)) {
                KeyPairUtils.writeKeyPair(keyPair, fw);
            }
            return keyPair;
        }
        else {
            try(FileReader fr = new FileReader(keyPairFile)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        }
    }

}