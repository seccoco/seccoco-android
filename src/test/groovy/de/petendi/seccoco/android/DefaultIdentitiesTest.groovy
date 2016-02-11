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
package de.petendi.seccoco.android

import de.petendi.commons.crypto.Certificates
import de.petendi.seccoco.android.connector.SCSecurityProviderConnector
import de.petendi.seccoco.android.model.Identity
import junit.framework.Assert
import spock.lang.Specification

import java.security.cert.X509Certificate

class DefaultIdentitiesTest extends Specification {
    def "ExtractFromValidPem"() {
        given:
        SCSecurityProviderConnector securityProviderConnector = new SCSecurityProviderConnector();
        Certificates certificates = new Certificates(securityProviderConnector);
        StringWriter pemWriter = new StringWriter();
        certificates.create("test-user","test-password".toCharArray(),pemWriter,new ByteArrayOutputStream());
        String certificateString = pemWriter.toString();
        when:
        DefaultIdentities defaultIdentities = new DefaultIdentities(securityProviderConnector);
        Identity extractedIdentity = defaultIdentities.extractFromPem(new StringReader(certificateString));
        then:
        X509Certificate extractedCertificate = securityProviderConnector.extractCertificate(new StringReader(certificateString));
        Assert.assertEquals(Utils.extractFingerPrint(extractedCertificate),extractedIdentity.getFingerPrint());
    }

    def "ExtractFromInvalidPem"() {
        given:
        String certificateString = "---BEGIN CERTIFICATE oh well this is broken END CERTIFICATE---";
        when:
        SCSecurityProviderConnector securityProviderConnector = new SCSecurityProviderConnector();
        DefaultIdentities defaultIdentities = new DefaultIdentities(securityProviderConnector);
        defaultIdentities.extractFromPem(new StringReader(certificateString));
        then:
        thrown IllegalArgumentException;
    }
}
