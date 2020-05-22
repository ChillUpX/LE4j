/**
 * LE4j - ACME client for obtaining lets encrypt certificates as keystore.
 *
 * Copyright 2020 Rony "ChillUpX" Tesch
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

import io.undertow.Undertow;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;

@Slf4j
@Builder
@RequiredArgsConstructor
public class HttpChallengeSolver {

    private final Authorization auth;
    private final Http01Challenge challenge;
    private final String domain;
    private final long timeBetweenRetry;

    /**
     * This method solves Http01Challenges with setting up a temporary webserver
     * @throws Exception
     */
    public void solve() throws Exception {
        String challengeFile = "http://"+domain+"/.well-known/acme-challenge/"+challenge.getToken();
        Undertow undertow = Undertow.builder().addHttpListener(80, "0.0.0.0", exchange -> {
            // Return invalid requests
            if(!exchange.getRequestURL().equals(challengeFile)) {
                exchange.getResponseSender().send("");
            }
            // Return authorization code if valid path
            exchange.getResponseSender().send(challenge.getAuthorization());
        }).build();

        undertow.start();

        challenge.trigger();

        // Wait for challenge to finish
        int times = 0;
        while(auth.getStatus() != Status.VALID) {
            if(times >= 10) {
                throw new AcmeException("Failed to authenticate certifacte for " + domain);
            }

            Thread.sleep(timeBetweenRetry);
            auth.update();
            times++;
        }

        // Stop webserver
        undertow.stop();
    }
}
