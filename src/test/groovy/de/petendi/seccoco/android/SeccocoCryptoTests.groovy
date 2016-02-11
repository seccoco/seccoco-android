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
import android.content.res.AssetManager
import de.petendi.commons.crypto.Certificates
import de.petendi.seccoco.android.connector.SCSecurityProviderConnector
import junit.framework.Assert
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class SeccocoCryptoTests extends AbstractSpecification {

    @Rule
    private TemporaryFolder temporaryFolder = new TemporaryFolder();

    def "creates application password if not configured"() {
        given:
        File emptySeccocoFolder = temporaryFolder.newFolder();
        def mockContext = Mock(Context);
        mockContext.getDir(_ as String,Context.MODE_PRIVATE)>>emptySeccocoFolder;
        def mockAssetManager =  Mock(AssetManager);
        mockContext.getAssets() >> mockAssetManager;
        mockAssetManager.open(_ as String) >> {throw new FileNotFoundException()};
        when:
        SeccocoImpl  impl = new SeccocoImpl(mockContext,MOCK_ROOTPASSWORD);
        impl.unlock();
        String testStr = "test";
        byte[] test = testStr.bytes;
        byte[] enc = impl.crypto().encrypt(test);
        then:
        Assert.assertEquals(new String(impl.crypto().decrypt(enc)),testStr);
    }


    def "uses same application password if configured"() {
        given:
        File emptySeccocoFolder = temporaryFolder.newFolder();
        def mockContext = Mock(Context);
        mockContext.getDir(_ as String,Context.MODE_PRIVATE)>>emptySeccocoFolder;
        def mockAssetManager =  Mock(AssetManager);
        mockContext.getAssets() >> mockAssetManager;
        mockAssetManager.open(_ as String) >> {throw new FileNotFoundException()};
        when:
        SeccocoImpl  impl = new SeccocoImpl(mockContext,MOCK_ROOTPASSWORD);
        impl.unlock();
        String testStr = "test";
        byte[] test = testStr.bytes;
        byte[] enc = impl.crypto().encrypt(test);
        impl.release();
        SeccocoImpl implNew = new SeccocoImpl(mockContext,MOCK_ROOTPASSWORD);
        implNew.unlock();
        then:
        Assert.assertEquals(new String(implNew.crypto().decrypt(enc)),testStr);
    }

    def "decryption fails when released"() {
        given:
        File emptySeccocoFolder = temporaryFolder.newFolder();
        def mockContext = Mock(Context);
        mockContext.getDir(_ as String,Context.MODE_PRIVATE)>>emptySeccocoFolder;
        when:
        SeccocoImpl  impl = new SeccocoImpl(mockContext,MOCK_ROOTPASSWORD);
        impl.unlock();
        String testStr = "test";
        byte[] test = testStr.bytes;
        byte[] enc = impl.crypto().encrypt(test);
        impl.release();
        impl.crypto().decrypt(enc);
        then:
        thrown IllegalStateException;
    }

    def "decryption fails when released also from reused crypto object, because appsecret is cleared"() {
        given:
        File emptySeccocoFolder = temporaryFolder.newFolder();
        def mockContext = Mock(Context);
        mockContext.getDir(_ as String,Context.MODE_PRIVATE)>>emptySeccocoFolder;
        when:
        SeccocoImpl  impl = new SeccocoImpl(mockContext,MOCK_ROOTPASSWORD);
        impl.unlock();
        String testStr = "test";
        byte[] test = testStr.bytes;
        Crypto crypto = impl.crypto();
        byte[] enc = crypto.encrypt(test);
        impl.release();
        crypto.decrypt(enc);
        then:
        thrown IllegalStateException;
    }

    def "create ECC Keypair"() {
        given:
        char[] pw = "123".toCharArray();
        StringWriter pemWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        when:
        Certificates certs = new Certificates(new SCSecurityProviderConnector());
        certs.create("myUser",pw,pemWriter,byteArrayOutputStream);
        then:
        Assert.assertNotNull(pemWriter);
    }

}
