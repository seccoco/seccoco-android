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
import android.content.SharedPreferences;

import org.cryptonode.jncryptor.AES256JNCryptorInputStream;
import org.cryptonode.jncryptor.AES256JNCryptorOutputStream;
import org.cryptonode.jncryptor.CryptorException;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;


public class DefaultIO implements IO {

    private final char[] appSecret;
    private final Context context;
    private final Crypto crypto;

    public DefaultIO(char[] appSecret, Context context,Crypto crypto) {
        this.appSecret = appSecret;
        this.context = context;
        this.crypto = crypto;
    }

    @Override
    public OutputStream openFileOutput(String name, int mode) throws FileNotFoundException {
        try {
            return new AES256JNCryptorOutputStream(context.openFileOutput(name,mode),appSecret);
        } catch (CryptorException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public InputStream openFileInput(String name) throws FileNotFoundException {
        return new AES256JNCryptorInputStream(context.openFileInput(name),appSecret);
    }

    @Override
    public SharedPreferences getSharedPreferences(String name, int mode) {
        return new EncryptedSharedPreferences(context.getSharedPreferences(name,mode),crypto);
    }
}
