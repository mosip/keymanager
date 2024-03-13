package io.mosip.kernel.keymanager.hsm.test;

import io.mosip.kernel.core.keymanager.exception.KeystoreProcessingException;
import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerErrorCode;
import io.mosip.kernel.keymanager.hsm.impl.offline.OLKeyStoreImpl;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class OLKeyStoreImplTest {

    @Test
    public void testGetAllAlias() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.getAllAlias();
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGetKey() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.getKey("alias");
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGetAsymmetricKey() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.getAsymmetricKey("alias");
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.getPrivateKey("alias");
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGetPublicKey() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.getPublicKey("alias");
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGetCertificate() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.getCertificate("alias");
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGetSymmetricKey() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.getSymmetricKey("alias");
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testDeleteKey() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.deleteKey("alias");
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGenerateAndStoreAsymmetricKey() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            CertificateParameters certificateParameters=new CertificateParameters();
            keystore.generateAndStoreAsymmetricKey("alias","signKeyAlias",certificateParameters);
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGenerateAndStoreSymmetricKey() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.generateAndStoreSymmetricKey("alias");
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

    @Test
    public void testGetKeystoreProviderName() throws Exception {
        OLKeyStoreImpl keystore = new OLKeyStoreImpl(null);
        try {
            keystore.getKeystoreProviderName();
        } catch (KeystoreProcessingException e) {
            assertEquals(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode(), e.getErrorCode());
        }
    }

}
