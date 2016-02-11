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

import android.content.Context;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.util.Properties;


import de.petendi.commons.crypto.AsymmetricCrypto;
import de.petendi.commons.crypto.connector.SecurityProviderConnector;
import de.petendi.seccoco.android.connector.AndroidSecurityProviderConnector;
import de.petendi.seccoco.android.connector.SCSecurityProviderConnector;
import de.petendi.seccoco.android.model.Identity;

class SeccocoImpl implements Seccoco {

    private static class InitializationResult {
        enum Type {
            P12,
            ANDROID_KEYSTORE
        }

        private Type type;
        private int version;

        public Type getType() {
            return type;
        }

        public void setType(Type type) {
            this.type = type;
        }

        public int getVersion() {
            return version;
        }

        public void setVersion(int version) {
            this.version = version;
        }
    }

    private static final byte[] NULL_ROOT_PASSWORD = new byte[0];
    private static final String SECCOCO_PROPS = "seccoco.props";
    private static final String SECCOCO_PROPS_VERSION_KEY = "version";
    private static final String SECCOCO_PROPS_TYPE_KEY = "type";
    private static final String SECCOCO_TRUSTEDRECIPIENT_ASSET = "seccoco-trustedrecipient.pem";
    private static final InitializationResult NULL_RESULT = new InitializationResult();


    private Token token = null;
    private InitializationResult initializationResult;
    private final InitializationParameters initializationParameters;
    private char[] appSecret = null;
    private final Context context;
    private final byte[] rootPassword;
    private Identity serverIdentity = null;

    SeccocoImpl(Context context) {
        this(context, NULL_ROOT_PASSWORD);
    }

    SeccocoImpl(Context context, byte[] rootPassword) {
        this.context = context;
        this.rootPassword = rootPassword;
        File dataDirectory = context.getDir(Constants.SECCOCO, Context.MODE_PRIVATE);
        initializationParameters = new InitializationParameters(dataDirectory);
        initialize();
    }

    private void initialize() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        File configurationFile = new File(initializationParameters.getDataDirectory(), SECCOCO_PROPS);
        if (configurationFile.exists()) {
            initializationResult = readInitializationResult(configurationFile);
        } else {
            initializationResult = NULL_RESULT;
        }
    }

    void release() {
        char[] random = Utils.randomString(appSecret.length).toCharArray();
        System.arraycopy(random,0,appSecret,0,appSecret.length);
        initializationResult = NULL_RESULT;
        token = null;
    }

    @Override
    public UnlockResult unlock() {
        if (!isLocked()) {
            throw new UnlockFailedException("already initialized");
        }
        File dataDirectory = initializationParameters.getDataDirectory();
        File passwordFile = new File(initializationParameters.getDataDirectory(), "metadata.dat");
        final String dat1 = "dat1";
        Configurator configurator;
        if (isConfigured()) {
            configurator = getConfigurator(initializationResult,dataDirectory);
        } else {
            configurator = configureInitially(dataDirectory);
        }
        token = configurator.readToken();

        if (passwordFile.exists()) {
            readAppPassword(dat1, passwordFile);
        } else {
            storeAppPassword(dat1, passwordFile);

        }
        readServerCertificateIfAvailable();
        return configurator.getUnlockResult();

    }

    private Configurator configureInitially(File dataDirectory) {
        Configurator configurator;
        boolean keyStoreAvailable = false;
        try {
            KeyStore.getInstance(Constants.ANDROID_KEY_STORE);
            keyStoreAvailable = true;
        } catch (KeyStoreException e) {
            //swallow
        }
        InitializationResult result = new InitializationResult();
        result.setVersion(1);
        if (keyStoreAvailable) {
            result.setType(InitializationResult.Type.ANDROID_KEYSTORE);
        } else {
            if(NULL_ROOT_PASSWORD==rootPassword) {
                throw new IllegalStateException("legacy support disabled");
            }
            result.setType(InitializationResult.Type.P12);
        }
        configurator = getConfigurator(result, dataDirectory);

        if (!configurator.isConfigured()) {
            configurator.configure();
        }
        this.initializationResult = result;
        storeInitializationResult(result);
        return configurator;
    }

    private Configurator getConfigurator(InitializationResult initializationResult, File dataDirectory) {
        Configurator configurator;
        switch (initializationResult.getType()) {
            case P12:
                if(NULL_ROOT_PASSWORD==rootPassword) {
                    throw new IllegalStateException("legacy support disabled");
                }
                configurator = new PKCS12Configurator(dataDirectory,rootPassword);
                break;
            case ANDROID_KEYSTORE:
                configurator = new AndroidKeyStoreConfigurator();
                break;
            default:
                throw new IllegalStateException("unhandled case: " + initializationResult.getType());
        }
        return configurator;
    }

    private void readServerCertificateIfAvailable() {
        try {
            InputStream inputStream = context.getAssets().open(SECCOCO_TRUSTEDRECIPIENT_ASSET);
            serverIdentity = identities().extractFromPem(new InputStreamReader(inputStream));
        } catch(FileNotFoundException e) {
            //swallow
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private InitializationResult readInitializationResult(File configurationFile) {
        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(configurationFile));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        InitializationResult result = new InitializationResult();
        try {
            int version = Integer.parseInt(properties.getProperty(SECCOCO_PROPS_VERSION_KEY, "1"));
            result.setVersion(version);
            result.setType(InitializationResult.Type.valueOf(properties.getProperty(SECCOCO_PROPS_TYPE_KEY, "NOT_VALID")));
        } catch (Exception e) {
            throw new IllegalArgumentException("seccoco.props contains invalid data",e);
        }
        return result;
    }

    private void storeInitializationResult(InitializationResult result) {
        File configurationFile = new File(initializationParameters.getDataDirectory(), SECCOCO_PROPS);
        Properties properties = new Properties();
        properties.put(SECCOCO_PROPS_VERSION_KEY,Integer.toString(result.getVersion()));
        properties.put(SECCOCO_PROPS_TYPE_KEY,result.getType().toString());
        try {
            properties.store(new FileWriter(configurationFile), Constants.SECCOCO);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private void readAppPassword(String dat1, File passwordFile) {
        Properties metaDataProps = new Properties();
        try {
            metaDataProps.load(new FileReader(passwordFile));
            String encBase64 = metaDataProps.getProperty(dat1);
            byte[] enc = Base64.decode(encBase64);
            AsymmetricCrypto asymmetricCrypto;
            byte[] decrypted;
            if (token instanceof AndroidKeyStoreToken) {
                asymmetricCrypto = new AsymmetricCrypto(new AndroidSecurityProviderConnector());
                decrypted = asymmetricCrypto.decrypt(enc, ((AndroidKeyStoreToken) token).getPrivateKey());
            } else {
                PKCS12Token pkcs12Token = (PKCS12Token) token;
                asymmetricCrypto = new AsymmetricCrypto(new SCSecurityProviderConnector());
                decrypted = asymmetricCrypto.decrypt(enc, pkcs12Token.getPin(), new ByteArrayInputStream(pkcs12Token.getPkcs12()));
            }
            appSecret = Base64.toBase64String(decrypted).toCharArray();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private void storeAppPassword(String key, File passwordFile) {
        Properties metaDataProps = new Properties();
        SecurityProviderConnector  bridge;
        if(initializationResult.getType()== InitializationResult.Type.ANDROID_KEYSTORE) {
            bridge = new AndroidSecurityProviderConnector();
        } else {
            bridge = new SCSecurityProviderConnector();
        }
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(bridge);

        byte[] password = new SCSecurityProviderConnector().generateSecretKey().getEncoded();
        appSecret = Base64.toBase64String(password).toCharArray();
        byte[] encryptedPassword = asymmetricCrypto.encrypt(password, new StringReader(token.getIdentity().getCertificate()));
        byte[] base64 = Base64.encode(encryptedPassword);
        metaDataProps.put(key, new String(base64));
        try {
            metaDataProps.store(new FileWriter(passwordFile), "Data");
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }




    @Override
    public boolean isLocked() {
        return token == null;
    }

    private boolean isConfigured() {
        return initializationResult != NULL_RESULT;
    }


    @Override
    public Crypto crypto() {
        if(isLocked()) {
            throw new IllegalStateException("seccoco locked");
        } else {
            return new DefaultCrypto(token, appSecret, serverIdentity);
        }

    }

    @Override
    public Identities identities() {
        return new DefaultIdentities(new SCSecurityProviderConnector());
    }

    @Override
    public IO io() {
        if(isLocked()) {
            throw new IllegalStateException("seccoco locked");
        } else {
            return new DefaultIO(appSecret,context, crypto());
        }

    }

}
