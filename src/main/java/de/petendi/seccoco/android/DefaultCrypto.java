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

import java.io.ByteArrayInputStream;
import java.io.StringReader;

import de.petendi.commons.crypto.HybridCrypto;
import de.petendi.commons.crypto.SymmetricCrypto;
import de.petendi.commons.crypto.connector.SecurityProviderConnector;
import de.petendi.commons.crypto.model.HybridEncrypted;
import de.petendi.seccoco.android.connector.AndroidSecurityProviderConnector;
import de.petendi.seccoco.android.connector.SCSecurityProviderConnector;
import de.petendi.seccoco.android.model.EncryptedMessage;
import de.petendi.seccoco.android.model.Identity;

class DefaultCrypto implements Crypto {

    private static  final Identity NULL_IDENTITY = new Identity("","");

    private final Token token;
    private final char[] appSecret;
    private final Identity ownIdentity;
    private final Identity serverIdentity;

    DefaultCrypto(Token token, char[] appSecret, Identity serverIdentity) {
        this.token = token;
        this.appSecret = appSecret;
        this.ownIdentity = token.getIdentity();
        if(serverIdentity!=null) {
            this.serverIdentity = serverIdentity;
        } else {
            this.serverIdentity = NULL_IDENTITY;
        }

    }


    private SecurityProviderConnector createSecurityProviderBridge() {
        if (token instanceof PKCS12Token) {
            return new SCSecurityProviderConnector();
        } else {
            return new AndroidSecurityProviderConnector();
        }
    }

    @Override
    public byte[] decrypt(EncryptedMessage message) {
        HybridCrypto hybridCrypto = new HybridCrypto(createSecurityProviderBridge());
        if (token instanceof PKCS12Token) {
            PKCS12Token pkcs12Token = (PKCS12Token) token;
            return hybridCrypto.decrypt(toHybridEncrypted(message), token.getIdentity().getFingerPrint(), pkcs12Token.getPin(), new ByteArrayInputStream(pkcs12Token.getPkcs12()));
        } else {
            AndroidKeyStoreToken androidKeyStoreToken = (AndroidKeyStoreToken) token;
            return hybridCrypto.decrypt(toHybridEncrypted(message), token.getIdentity().getFingerPrint(), androidKeyStoreToken.getPrivateKey());
        }
    }

    @Override
    public EncryptedMessage encryptForSelf(byte[] message) {
        return encrypt(message,ownIdentity);
    }

    @Override
    public EncryptedMessage encryptForTrustedRecipient(byte[] message) {
        if(NULL_IDENTITY==serverIdentity) {
            throw new IllegalStateException("no server identity added");
        } else {
            return encrypt(message,serverIdentity);
        }
    }

    @Override
    public EncryptedMessage encrypt(byte[] message, Identity identity) {
        HybridCrypto hybridCrypto = new HybridCrypto(createSecurityProviderBridge());
        hybridCrypto.addRecipient(identity.getFingerPrint(), new StringReader(identity.getCertificate()));
        if (token instanceof PKCS12Token) {
            PKCS12Token pkcs12Token = (PKCS12Token) token;
            HybridEncrypted encrypted = hybridCrypto.build(message, pkcs12Token.getPin(), new ByteArrayInputStream(pkcs12Token.getPkcs12()));
            return toEncryptedMessage(encrypted);
        } else {
            AndroidKeyStoreToken androidKeyStoreToken = (AndroidKeyStoreToken) token;
            HybridEncrypted encrypted = hybridCrypto.build(message, androidKeyStoreToken.getPrivateKey());
            return toEncryptedMessage(encrypted);
        }
    }

    @Override
    public byte[] encrypt(byte[] plain) {
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
        return symmetricCrypto.encrypt(plain, appSecret);
    }

    @Override
    public byte[] decrypt(byte[] encrypted) {
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
        return symmetricCrypto.decrypt(encrypted, appSecret);
    }


    private static HybridEncrypted toHybridEncrypted(EncryptedMessage encryptedMessage) {
        HybridEncrypted hybridEncrypted = new HybridEncrypted();
        hybridEncrypted.setCertificates(encryptedMessage.getCertificates());
        hybridEncrypted.setEncryptedBody(encryptedMessage.getEncryptedBody());
        hybridEncrypted.setHeaders(encryptedMessage.getHeaders());
        hybridEncrypted.setSignature(encryptedMessage.getSignature());
        hybridEncrypted.setRecipients(encryptedMessage.getRecipients());
        return hybridEncrypted;
    }

    private static EncryptedMessage toEncryptedMessage(HybridEncrypted hybridEncrypted) {
        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.setCertificates(hybridEncrypted.getCertificates());
        encryptedMessage.setEncryptedBody(hybridEncrypted.getEncryptedBody());
        encryptedMessage.setHeaders(hybridEncrypted.getHeaders());
        encryptedMessage.setSignature(hybridEncrypted.getSignature());
        encryptedMessage.setRecipients(hybridEncrypted.getRecipients());
        return encryptedMessage;
    }
    

}
