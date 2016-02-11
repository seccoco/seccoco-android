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

import android.content.SharedPreferences;
import android.util.Base64;

import org.apache.commons.lang3.NotImplementedException;

import java.util.Map;
import java.util.Set;

public class EncryptedSharedPreferences implements SharedPreferences {

    private class Editor implements SharedPreferences.Editor {

        private final SharedPreferences.Editor delegate;

        private Editor(SharedPreferences.Editor delegate) {
            this.delegate = delegate;
        }

        @Override
        public SharedPreferences.Editor putString(String key, String value) {
            delegate.putString(key, encrypt(value));
            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) {
            throw new NotImplementedException("method not implemented");
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            delegate.putString(key, encrypt(String.valueOf(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            delegate.putString(key, encrypt(String.valueOf(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            delegate.putString(key, encrypt(String.valueOf(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            delegate.putString(key, encrypt(String.valueOf(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            delegate.remove(key);
            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            delegate.clear();
            return this;
        }

        @Override
        public boolean commit() {
            return delegate.commit();
        }

        @Override
        public void apply() {
            delegate.commit();
        }
    }

    private final SharedPreferences sharedPreferences;
    private final Crypto crypto;

    public EncryptedSharedPreferences(SharedPreferences sharedPreferences, Crypto crypto) {
        this.sharedPreferences = sharedPreferences;
        this.crypto = crypto;
    }

    @Override
    public Map<String, ?> getAll() {
        throw new NotImplementedException("method not supported");
    }


    @Override
    public String getString(String key, String defValue) {
        String defString = "" + defValue;
        String value = sharedPreferences.getString(key, defString);
        if (notEquals(defString, value)) {
            return decrypt(value);
        } else {
            return defValue;
        }
    }

    @Override
    public Set<String> getStringSet(String key, Set<String> defValues) {
        throw new NotImplementedException("method not implemented");
    }

    @Override
    public int getInt(String key, int defValue) {
        String defString = Integer.toString(defValue);
        String value = sharedPreferences.getString(key, defString);
        if (notEquals(defString, value)) {
            return Integer.parseInt(decrypt(value));
        } else {
            return defValue;
        }

    }

    @Override
    public long getLong(String key, long defValue) {
        String defString = Long.toString(defValue);
        String value = sharedPreferences.getString(key, defString);
        if (notEquals(defString, value)) {
            return Long.parseLong(decrypt(value));
        } else {
            return defValue;
        }
    }

    @Override
    public float getFloat(String key, float defValue) {
        String defString = Float.toString(defValue);
        String value = sharedPreferences.getString(key, defString);
        if (notEquals(defString, value)) {
            return Float.parseFloat(decrypt(value));
        } else {
            return defValue;
        }
    }

    @Override
    public boolean getBoolean(String key, boolean defValue) {
        String defString = Boolean.toString(defValue);
        String value = sharedPreferences.getString(key, defString);
        if (notEquals(defString, value)) {
            return Boolean.parseBoolean(decrypt(value));
        } else {
            return defValue;
        }
    }

    @Override
    public boolean contains(String key) {
        return sharedPreferences.contains(key);
    }

    @Override
    public Editor edit() {
        return new Editor(sharedPreferences.edit());
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        sharedPreferences.registerOnSharedPreferenceChangeListener(listener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        sharedPreferences.unregisterOnSharedPreferenceChangeListener(listener);
    }

    private String encrypt(String value) {
        return Base64.encodeToString(crypto.encrypt(value.getBytes()),Base64.DEFAULT);
    }

    private String decrypt(String value) {
        return new String(crypto.decrypt(Base64.decode(value.getBytes(),Base64.DEFAULT)));
    }

    private static boolean notEquals(Object a, Object b) {
            return !((a == null) ? (b == null) : a.equals(b));
    }
}
