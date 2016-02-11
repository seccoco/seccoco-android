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

public final class SeccocoFactory {

    private static SeccocoImpl instance;

    private SeccocoFactory() {
        //hide
    }


    public static final synchronized Seccoco create(Context applicationContext) {
        if(instance==null) {
            PRNGFixes.apply();
            instance = new SeccocoImpl(applicationContext);
            return instance;
        } else {
            throw new IllegalStateException("seccoco already initialized");
        }
    }

    public static final synchronized Seccoco createWithLegacySupport(Context applicationContext,byte[] rootPassword) {
        if(instance==null) {
            PRNGFixes.apply();
            instance = new SeccocoImpl(applicationContext,rootPassword);
            return instance;
        } else {
            throw new IllegalStateException("seccoco already initialized");
        }
    }

    public static final synchronized void release() {
        if(instance!=null) {
            instance.release();
            instance = null;
        }
    }
}
