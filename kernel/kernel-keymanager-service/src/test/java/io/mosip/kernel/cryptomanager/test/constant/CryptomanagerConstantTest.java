
package io.mosip.kernel.cryptomanager.test.constant;

import io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class CryptomanagerConstantTest {

    @Test
    public void stringConstantTest() {
        assertEquals(" ", CryptomanagerConstant.WHITESPACE);
        assertEquals("should not be null or empty", CryptomanagerConstant.INVALID_REQUEST);
        assertEquals("should not be empty", CryptomanagerConstant.EMPTY_ATTRIBUTE);
        assertEquals(".+\\S.*", CryptomanagerConstant.EMPTY_REGEX);
        assertEquals("CryptoManagerSession", CryptomanagerConstant.SESSIONID);
        assertEquals("CryptoManagerEncrypt", CryptomanagerConstant.ENCRYPT);
        assertEquals("CryptoManagerDecrypt", CryptomanagerConstant.DECRYPT);
        assertEquals("CryptoManagerEncryptWithPin", CryptomanagerConstant.ENCRYPT_PIN);
        assertEquals("CryptoManagerDecryptWithPin", CryptomanagerConstant.DECRYPT_PIN);
        assertEquals("NA", CryptomanagerConstant.NOT_APPLICABLE);
        assertEquals("Crypto-Manager-JWEEncrypt", CryptomanagerConstant.JWT_ENCRYPT);
        assertEquals("Crypto-Manager-JWEDecrypt", CryptomanagerConstant.JWT_DECRYPT);
        assertEquals("cty", CryptomanagerConstant.JSON_CONTENT_TYPE_KEY);
        assertEquals("JWT", CryptomanagerConstant.JSON_CONTENT_TYPE_VALUE);
        assertEquals("jku", CryptomanagerConstant.JSON_HEADER_JWK_KEY);
        assertEquals("typ", CryptomanagerConstant.JSON_HEADER_TYPE_KEY);
        assertEquals("Crypto-Manager-Gen-Argon2-Hash", CryptomanagerConstant.GEN_ARGON2_HASH);
        assertEquals("cacheAESKey", CryptomanagerConstant.CACHE_AES_KEY);
        assertEquals("cacheIntCounter", CryptomanagerConstant.CACHE_INT_COUNTER);
    }

    @Test
    public void numericConstantTest() {
        assertEquals(32, CryptomanagerConstant.THUMBPRINT_LENGTH);
        assertEquals(256, CryptomanagerConstant.ENCRYPTED_SESSION_KEY_LENGTH);
        assertEquals(32, CryptomanagerConstant.GCM_AAD_LENGTH);
        assertEquals(12, CryptomanagerConstant.GCM_NONCE_LENGTH);
    }

    @Test
    public void booleanConstantTest() {
        assertEquals(Boolean.FALSE, CryptomanagerConstant.DEFAULT_INCLUDES_FALSE);
        assertEquals(Boolean.TRUE, CryptomanagerConstant.DEFAULT_INCLUDES_TRUE);
    }

    @Test
    public void byteArrayConstantTest() {
        assertArrayEquals(CryptomanagerConstant.VERSION_RSA_2048, "VER_R2".getBytes());
    }
}
