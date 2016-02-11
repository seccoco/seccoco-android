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

import android.content.Context
import android.content.SharedPreferences
import android.content.res.AssetManager
import junit.framework.Assert
import org.apache.commons.io.IOUtils
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import org.robolectric.RuntimeEnvironment

class DefaultIOTest extends AbstractSpecification {



    @Rule
    private TemporaryFolder temporaryFolder = new TemporaryFolder();

    def "test file crypto"() {
        given:
        File emptySeccocoFolder = temporaryFolder.newFolder();
        def mockContext = Mock(Context);
        mockContext.getDir(_ as String, Context.MODE_PRIVATE) >> emptySeccocoFolder;
        def mockAssetManager =  Mock(AssetManager);
        mockContext.getAssets() >> mockAssetManager;
        mockAssetManager.open(_ as String) >> {throw new FileNotFoundException()};
        File fileToWriter = temporaryFolder.newFile();
        mockContext.openFileOutput(_ as String, Context.MODE_PRIVATE) >> new FileOutputStream(fileToWriter);
        mockContext.openFileInput(_ as String) >> new FileInputStream(fileToWriter);
        SeccocoImpl impl = new SeccocoImpl(mockContext,MOCK_ROOTPASSWORD);
        impl.unlock();
        when:
        String secretMessage = "this is a secret message";
        OutputStream outputStream = impl.io().openFileOutput("test",Context.MODE_PRIVATE);
        IOUtils.write(secretMessage.bytes, outputStream);
        IOUtils.closeQuietly(outputStream);
        InputStream inputStream = impl.io().openFileInput("test");
        String readMessage = IOUtils.toString(inputStream);
        IOUtils.closeQuietly(inputStream);
        then:
        Assert.assertEquals(readMessage,secretMessage)
    }

    def "test encrypted sharedpreferences"() {
        given:
        def context = RuntimeEnvironment.application;
        def contextMock = Mock(Context);
        def mockAssetManager =  Mock(AssetManager);
        contextMock.getAssets() >> mockAssetManager;
        contextMock.getSharedPreferences(_ as String,Context.MODE_PRIVATE) >> context.getSharedPreferences("test_pref", Context.MODE_PRIVATE);
        mockAssetManager.open(_ as String) >> {throw new FileNotFoundException()};
        File emptySeccocoFolder = temporaryFolder.newFolder();
        contextMock.getDir(_ as String, Context.MODE_PRIVATE) >> emptySeccocoFolder;
        File fileToWriter = temporaryFolder.newFile();
        contextMock.openFileOutput(_ as String, Context.MODE_PRIVATE) >> new FileOutputStream(fileToWriter);
        contextMock.openFileInput(_ as String) >> new FileInputStream(fileToWriter);
        SeccocoImpl impl = new SeccocoImpl(contextMock,MOCK_ROOTPASSWORD);
        impl.unlock();
        when:
        SharedPreferences sharedPreferences = impl.io().getSharedPreferences("test_pref",Context.MODE_PRIVATE);
        final String stringKey = "stringKey";
        final String stringValue = "stringValue";
        final String intKey = "intKey";
        final int intValue = 1543;
        final String longKey = "longKey";
        final long longValue = 764567654332223345;
        final String floatKey = "floatKey";
        final float floatValue = 0.0003;
        final String booleanKey = "booleanKey";
        final boolean booleanValue = true;


        sharedPreferences.edit()
                .putString(stringKey,stringValue)
                .putInt(intKey,intValue)
                .putLong(longKey,longValue)
                .putFloat(floatKey,floatValue)
                .putBoolean(booleanKey,booleanValue)
                .commit();
        SharedPreferences persisted = impl.io().getSharedPreferences("test_pref",Context.MODE_PRIVATE);
        then:
        Assert.assertEquals(stringValue,persisted.getString(stringKey,"nope"));
        Assert.assertEquals(intValue,persisted.getInt(intKey,-3));
        Assert.assertEquals(longValue,persisted.getLong(longKey,-1));
        Assert.assertEquals(floatValue,persisted.getFloat(floatKey,(float)-1.9));
        Assert.assertEquals(booleanValue,persisted.getBoolean(booleanKey,false));
    }
}
