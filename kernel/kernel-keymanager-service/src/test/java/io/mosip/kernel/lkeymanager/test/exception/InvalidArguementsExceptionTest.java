package io.mosip.kernel.lkeymanager.test.exception;

import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.lkeymanager.exception.InvalidArgumentsException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;

@RunWith(MockitoJUnitRunner.class)
public class InvalidArguementsExceptionTest {

    @Mock
    private InvalidArgumentsException exception;

    @Test
    public void testGetList() {
        List<ServiceError> errorList = new ArrayList<>();
        errorList.add(new ServiceError("ERROR_CODE_1", "Error 1"));
        errorList.add(new ServiceError("ERROR_CODE_2", "Error 2"));
        Mockito.when(exception.getList()).thenReturn(errorList);
        List<ServiceError> retrievedList = exception.getList();
        Assert.assertEquals(errorList, retrievedList);
    }

    @Test
    public void testGetList_EmptyList() {
        List<ServiceError> errorList = new ArrayList<>();
        Mockito.when(exception.getList()).thenReturn(errorList);
        List<ServiceError> retrievedList = exception.getList();
        Assert.assertTrue(retrievedList.isEmpty());
    }

}
