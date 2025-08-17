package io.mosip.kernel.zkcryptoservice.exception;

import org.junit.Assert;
import org.junit.Test;

public class ZKRandomKeyDecryptionExceptionTest {
    @Test
    public void testConstructorWithErrorMessage() {
        String errorCode = "ERROR_CODE";
        String errorMessage = "Error message";

        ZKRandomKeyDecryptionException exception = new ZKRandomKeyDecryptionException(errorCode, errorMessage);

        Assert.assertEquals(errorCode, exception.getErrorCode());
    }
}
