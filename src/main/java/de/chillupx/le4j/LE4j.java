package de.chillupx.le4j;

import io.undertow.Undertow;
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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Slf4j
@Builder
@RequiredArgsConstructor
public class LE4j {

    public static final String ACME_LETSENCRYPT_STAGING = "acme://letsencrypt.org/staging";
    public static final String ACME_LETSENCRYPT = "acme://letsencrypt.org";

    public final String domain;
    public final String workdir;
    @Builder.Default public final boolean useStaging = false;

    public void obtainCert() throws IOException, AcmeException, InterruptedException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        //Create Account-Keypair if none exists
        boolean accountExists = getKeyPairFile("account.key").exists();
        KeyPair accountKeyPair = generateKeyPair("account.key");

        // Login
        Session session = new Session(useStaging ? ACME_LETSENCRYPT_STAGING : ACME_LETSENCRYPT);
        AccountBuilder accountBuilder = new AccountBuilder()
                .useKeyPair(accountKeyPair)
                .agreeToTermsOfService();
        if(accountExists) {
            accountBuilder.onlyExisting();
        }
        Account account = accountBuilder.create(session);

        // Create Order
        Order order = account.newOrder().domains(domain).create();

        // Authorize request with http challenge
        for(Authorization auth : order.getAuthorizations()) {
            if(auth.getStatus() != Status.VALID) {
                processAuthorization(auth);
            }
        }

        // Create Domain Key Pair
        KeyPair domainKeyPair = generateKeyPair(domain+".key");
        byte[] csr = generateCsr(domainKeyPair);

        log.info("Run order...");
        order.execute(csr);

        // wait for order to complete
        int counter = 0;
        while(order.getStatus() != Status.VALID) {
            if(counter >= 10) {
                log.error("Error while completing order..");
                System.exit(-1);
                break;
            }

            Thread.sleep(3000L);
            order.update();
            counter++;
        }

        Certificate cert = order.getCertificate();
        try(FileWriter fw = new FileWriter(new File(workdir, domain+".crt"))) {
            cert.writeCertificate(fw);
            log.info("Wrote certificate {}.crt into {}", domain, workdir);
        }

        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(null, null);
        ks.setKeyEntry(
                "key1",
                domainKeyPair.getPrivate(),
                "secure".toCharArray(),
                cert.getCertificateChain().toArray(new X509Certificate[]{})
        );
        ks.store(new FileOutputStream(new File(workdir, domain+".p12")), "secure".toCharArray());
        log.info("Wrote keystore {}.p12 to {}", domain, workdir);
    }

    private byte[] generateCsr(KeyPair domainKeyPair) throws IOException {
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomain(domain);
        csrb.setOrganization("gameserver.ac");
        csrb.sign(domainKeyPair);
        csrb.write(new FileWriter(new File(workdir, domain+".csr")));
        return csrb.getEncoded();
    }

    private void processAuthorization(Authorization auth) throws AcmeException, InterruptedException {
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        String challengeFile = "http://"+domain+"/.well-known/acme-challenge/"+challenge.getToken();

        log.info("Setting up challenge..");
        Undertow undertow = Undertow.builder().addHttpListener(80, "0.0.0.0", exchange -> {
            // Return invalid requests
            if(!exchange.getRequestURL().equals(challengeFile)) {
                exchange.getResponseSender().send("no!");
            }
            // Return authorization code if valid path
            exchange.getResponseSender().send(challenge.getAuthorization());
        }).build();
        undertow.start();

        log.info("Triggered challenge for {}", domain);
        challenge.trigger();

        // Wait for challenge to finish
        int times = 0;
        while(auth.getStatus() != Status.VALID && times < 10) {
            log.info("Challenge try #" + times);
            Thread.sleep(3000L);
            auth.update();
            times++;
        }

        // Stop webserver
        undertow.stop();
        if(auth.getStatus() == Status.VALID) {
            log.info("Successfully authenticated certificate for {}", domain);
        }
        else {
            log.error("Could not authenticate certificate for {}", domain);
            System.exit(-1);
        }
    }

    private KeyPair generateKeyPair(String name) throws IOException {
        return this.generateKeyPair(name, 2048);
    }

    private File getKeyPairFile(String name) {
        return new File(workdir, name);
    }

    private KeyPair generateKeyPair(String name, int keySize) throws IOException {
        File keyPairFile = getKeyPairFile(name);
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
