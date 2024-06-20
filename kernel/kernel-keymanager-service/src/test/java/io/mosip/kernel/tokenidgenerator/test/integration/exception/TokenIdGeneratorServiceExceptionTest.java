package io.mosip.kernel.tokenidgenerator.test.integration.exception;

import io.mosip.kernel.tokenidgenerator.exception.TokenIdGeneratorServiceException;
import org.junit.Assert;
import org.junit.Test;

public class TokenIdGeneratorServiceExceptionTest {

    @Test
    public void testConstructor() {
        String errorCode = "ERROR_CODE";
        String errorMessage = "Error message";

        TokenIdGeneratorServiceException exception = new TokenIdGeneratorServiceException(errorCode, errorMessage);

        Assert.assertEquals(errorCode, exception.getErrorCode());
    }
}
