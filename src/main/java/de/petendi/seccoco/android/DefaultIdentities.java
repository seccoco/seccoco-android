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

import org.apache.commons.io.IOUtils;

import java.io.Reader;
import java.io.StringReader;
import java.security.cert.X509Certificate;

import de.petendi.seccoco.android.connector.SCSecurityProviderConnector;
import de.petendi.seccoco.android.model.Identity;

class DefaultIdentities implements Identities {

    private final SCSecurityProviderConnector connector;

    DefaultIdentities(SCSecurityProviderConnector connector) {
        this.connector = connector;
    }

    @Override
    public Identity extractFromPem(Reader pemReader) {
        try {
            String certificate = IOUtils.toString(pemReader);
            X509Certificate x509Certificate = connector.extractCertificate(new StringReader(certificate));
            return new Identity(certificate,Utils.extractFingerPrint(x509Certificate));
        } catch (Exception e) {
            throw new IllegalArgumentException("could not extract certificate",e);
        }
    }
}
