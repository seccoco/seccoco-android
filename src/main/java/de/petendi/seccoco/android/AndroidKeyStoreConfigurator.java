/**
 * Copyright 2015  Jan Petendi <jan.petendi@p-acs.com>
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
package de.petendi.seccoco.android;


import java.io.StringWriter;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import de.petendi.commons.crypto.Certificates;
import de.petendi.commons.crypto.connector.SecurityProviderConnector;
import de.petendi.seccoco.android.connector.SCSecurityProviderConnector;
import de.petendi.seccoco.android.model.Identity;

class AndroidKeyStoreConfigurator extends Configurator {
    private static final String ALIAS = Constants.SECCOCO;
    private final SecurityProviderConnector securityProviderConnector = new SCSecurityProviderConnector();

    @Override
    boolean isConfigured() {
        try {
            KeyStore ks = KeyStore.getInstance(Constants.ANDROID_KEY_STORE);
            ks.load(null);
            return ks.containsAlias(ALIAS);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    Token readToken() {
        try {
            KeyStore ks = KeyStore.getInstance(Constants.ANDROID_KEY_STORE);
            ks.load(null);
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(ALIAS, null);
            X509Certificate certificate = (X509Certificate) entry.getCertificate();
            StringWriter pemWriter = new StringWriter();
            securityProviderConnector.writeCertificate(pemWriter, certificate);
            Identity identity = new Identity(pemWriter.toString(),Utils.extractFingerPrint(certificate));
            return new AndroidKeyStoreToken(identity,entry.getPrivateKey());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    void configure() {
        try {
            Certificates certificates = new Certificates(securityProviderConnector,Constants.SECCOCO,Constants.SECCOCO,null);
            String userId = createInstallationId();
            KeyStore ks = KeyStore.getInstance(Constants.ANDROID_KEY_STORE);
            ks.load(null);
            certificates.create(userId,ks);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    Seccoco.UnlockResult getUnlockResult() {
        return new Seccoco.UnlockResult(true);
    }
}
