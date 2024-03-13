package io.mosip.kernel.cryptomanager.test.exception;

import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.cryptomanager.exception.KeymanagerServiceException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class KeymanagerServiceExceptionTest {
    @Test
    public void testKeymanagerServiceException() {
        List<ServiceError> errorList = new ArrayList<>();
        errorList.add(new ServiceError("errorCode1", "errorDescription1"));
        errorList.add(new ServiceError("errorCode2", "errorDescription2"));
        KeymanagerServiceException exception = new KeymanagerServiceException(errorList);
        List<ServiceError> exceptionErrorList = exception.getList();
        assertEquals(errorList, exceptionErrorList);
    }
}
