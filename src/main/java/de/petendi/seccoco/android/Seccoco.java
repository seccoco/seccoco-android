/**
 * Copyright 2015  Jan Petendi <jan.petendi@p-acs.com>
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.petendi.seccoco.android;

public interface Seccoco {

    class UnlockResult {
        private final boolean secureEnvironment;

        public UnlockResult(boolean keyStore) {
            this.secureEnvironment = keyStore;
        }

        public boolean hasSecureEnvironment() {
            return secureEnvironment;
        }
    }

    class UnlockFailedException extends RuntimeException {
        UnlockFailedException(String message) {
            super(message);
        }
    }

    UnlockResult unlock();

    boolean isLocked();

    Crypto crypto();

    Identities identities();

    IO io();
}
