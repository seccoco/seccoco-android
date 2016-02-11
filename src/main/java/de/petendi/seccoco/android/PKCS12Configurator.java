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
import org.spongycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import de.petendi.commons.crypto.Certificates;
import de.petendi.commons.crypto.Hash;
import de.petendi.seccoco.android.connector.SCSecurityProviderConnector;
import de.petendi.seccoco.android.model.Identity;

class PKCS12Configurator extends Configurator {

    private final File keyFile;
    private final File certificateFile;
    private final File installationIdFile;
    private final File configurationActive;
    private final byte[] rootPassword;
    private String installationId = null;
    private String certificate = null;
    private byte[] pkcs12;

    PKCS12Configurator(File dataDirectory, byte[] rootPassword) {
        this.rootPassword = rootPassword;
        keyFile = new File(dataDirectory, "key.dat");
        certificateFile = new File(dataDirectory, "cert.dat");
        installationIdFile = new File(dataDirectory, "installationid.txt");
        configurationActive = new File(dataDirectory, "configuration_active");
    }
    private void init() {
        if (configurationActive.exists()) {
            certificateFile.delete();
            installationIdFile.delete();
            keyFile.delete();
            configurationActive.delete();
        }
        boolean installationDone = installationIdFile.exists();
        if (installationDone) {
            try {
                installationId = IOUtils.toString(new FileInputStream(installationIdFile));
                pkcs12 = IOUtils.toByteArray(new FileInputStream(keyFile));
                certificate = IOUtils.toString(new FileInputStream(certificateFile));
            } catch (IOException e) {
                throw new IllegalStateException("could not read file", e);
            }
        }

    }

    @Override
    boolean isConfigured() {
        return installationIdFile.exists();
    }

    @Override
    Token readToken() {
        if (isConfigured()) {
            try {
                installationId = IOUtils.toString(new FileInputStream(installationIdFile));
                pkcs12 = IOUtils.toByteArray(new FileInputStream(keyFile));
                certificate = IOUtils.toString(new FileInputStream(certificateFile));
                SCSecurityProviderConnector securityProviderBridge = new SCSecurityProviderConnector();
                X509Certificate x509Certificate = securityProviderBridge.extractCertificate(new StringReader(certificate));
                Identity identity = new Identity(certificate, Utils.extractFingerPrint(x509Certificate));
                Hash hash = new Hash(securityProviderBridge);
                byte[] hashedId = hash.hash(installationId.getBytes());
                byte[] combined = new byte[hashedId.length + rootPassword.length];
                System.arraycopy(hashedId, 0, combined, 0, hashedId.length);
                System.arraycopy(rootPassword, 0, combined, hashedId.length, rootPassword.length);
                String pinStr = extractPin();
                return new PKCS12Token(identity,pkcs12,pinStr.toCharArray());

            } catch (IOException e) {
                throw new IllegalStateException("could not read file", e);
            } catch (Exception e) {
                throw new IllegalStateException("error processing certificate", e);
            }
        } else {
            throw new IllegalStateException("not configured");
        }
    }

    private final String extractPin() {
        Hash hash = new Hash(new SCSecurityProviderConnector());
        byte[] hashedId = hash.hash(installationId.getBytes());
        byte[] combined = new byte[hashedId.length + rootPassword.length];
        System.arraycopy(hashedId, 0, combined, 0, hashedId.length);
        System.arraycopy(rootPassword, 0, combined, hashedId.length, rootPassword.length);
        return Arrays.toString(Base64.encode(combined));
    }

    @Override
    void configure() {
        try {
            configurationActive.createNewFile();
        } catch (IOException e) {
            throw new IllegalStateException("could not create configuration file",e);
        }
        installationId = createInstallationId();
        try {
            FileWriter installationIdWriter = new FileWriter(installationIdFile);
            Certificates certificates = new Certificates(new SCSecurityProviderConnector());
            FileWriter pemWriter = new FileWriter(certificateFile);
            FileOutputStream p12OutputStream = new FileOutputStream(keyFile);
            String pinStr = extractPin();
            certificates.create(installationId, pinStr.toCharArray(), pemWriter, p12OutputStream);
            IOUtils.write(installationId, installationIdWriter);
            IOUtils.closeQuietly(installationIdWriter);
            configurationActive.delete();
        } catch (IOException e) {
            throw new IllegalStateException("could not write installationId", e);
        }
        init();
    }

    @Override
    Seccoco.UnlockResult getUnlockResult() {
        return new Seccoco.UnlockResult(false);
    }
}
