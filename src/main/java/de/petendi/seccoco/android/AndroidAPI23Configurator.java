/**
 * Copyright 2016  Jan Petendi <jan.petendi@p-acs.com>
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

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.spongycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import de.petendi.commons.crypto.AsymmetricCrypto;
import de.petendi.commons.crypto.connector.SecurityProviderConnector;
import de.petendi.seccoco.android.connector.AndroidSecurityProviderConnector;
import de.petendi.seccoco.android.connector.SCSecurityProviderConnector;

public class AndroidAPI23Configurator extends Configurator {
    private PKCS12Configurator pkcs12Configurator;
    private final File dataDirectory;
    private char[] appSecret = null;

    private static final String ALIAS = Constants.SECCOCO + "AES";
    private static final String PASSWORD_FILE = "api23.props";

    public AndroidAPI23Configurator(File dataDirectory) {
        this.dataDirectory = dataDirectory;
        pkcs12Configurator = null;
    }

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
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(ALIAS, null);
            File passwordFile = new File(dataDirectory, PASSWORD_FILE);
            final String dat1 = "dat1";
            readAppPassword(dat1,passwordFile,key);
            pkcs12Configurator = new PKCS12Configurator(dataDirectory, new String(appSecret).getBytes());
            return pkcs12Configurator.readToken();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    void configure() {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, Constants.ANDROID_KEY_STORE);
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(ALIAS,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .build());
            SecretKey key = keyGenerator.generateKey();
            File passwordFile = new File(dataDirectory, PASSWORD_FILE);
            final String dat1 = "dat1";
            storeAppPassword(dat1,passwordFile,key);
            pkcs12Configurator = new PKCS12Configurator(dataDirectory, new String(appSecret).getBytes());
            pkcs12Configurator.configure();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

    }

    @Override
    Seccoco.UnlockResult getUnlockResult() {
        return pkcs12Configurator.getUnlockResult();
    }


    @TargetApi(Build.VERSION_CODES.M)
    private void readAppPassword(String dat1, File passwordFile, SecretKey key) {
        Properties metaDataProps = new Properties();
        try {
            metaDataProps.load(new FileReader(passwordFile));
            String encBase64 = metaDataProps.getProperty(dat1);
            String ivBase64 = metaDataProps.getProperty(dat1+"iv");
            byte[] iv = Base64.decode(ivBase64);
            byte[] enc = Base64.decode(encBase64);
            byte[] decrypted;
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128,iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key,gcmParameterSpec);

            decrypted = cipher.doFinal(enc);
            appSecret = Base64.toBase64String(decrypted).toCharArray();
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private void storeAppPassword(String key, File passwordFile,SecretKey secretKey) {
        Properties metaDataProps = new Properties();
        byte[] password = new SCSecurityProviderConnector().generateSecretKey().getEncoded();
        appSecret = Base64.toBase64String(password).toCharArray();
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] iv = cipher.getIV();
            byte[] encryptedPassword = cipher.doFinal(password);
            byte[] base64 = Base64.encode(encryptedPassword);
            byte[] base64Iv = Base64.encode(iv);
            metaDataProps.put(key, new String(base64));
            metaDataProps.put(key+"iv", new String(base64Iv));
                metaDataProps.store(new FileWriter(passwordFile), "Data");
        } catch (Exception e) {
           throw new IllegalArgumentException(e);
        }


    }
}
