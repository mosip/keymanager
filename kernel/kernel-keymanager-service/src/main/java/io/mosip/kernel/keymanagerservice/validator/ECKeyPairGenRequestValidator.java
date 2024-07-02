package io.mosip.kernel.keymanagerservice.validator;

import java.util.Arrays;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.keymanagerservice.constant.KeyReferenceIdConsts;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.entity.KeyPolicy;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;

/**
 * This class provides validation for ECC Key Pair generation.
 * 
 * @author Mahammed Taheer
 * @since 1.2.1
 *
 */
@Component
public class ECKeyPairGenRequestValidator {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(ECKeyPairGenRequestValidator.class);

    /**
	 * Utility to generate Metadata
	 */
	@Autowired
	KeymanagerUtil keymanagerUtil;

	/**
	 * KeymanagerDBHelper instance to handle all DB operations
	 */
	@Autowired
	private KeymanagerDBHelper dbHelper;

    public void validate(String responseType, KeyPairGenerateRequestDto keyPairGenerateRequestDto) {
        validateAllowedReferenceId(keyPairGenerateRequestDto.getApplicationId(), keyPairGenerateRequestDto.getReferenceId());
        validateResponseType(responseType);
    }

    private void validateAllowedReferenceId(String applicationId, String refId) {

		Optional<KeyPolicy> keyPolicy = dbHelper.getKeyPolicy(applicationId);
		if (!keymanagerUtil.isValidReferenceId(refId) || 
					!Arrays.stream(KeyReferenceIdConsts.values()).anyMatch((rId) -> rId.name().equals(refId)) || 
					applicationId.equals(KeymanagerConstant.ROOT)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, this.getClass().getSimpleName(), KeymanagerConstant.VALIDATE + keyPolicy.toString(),
									"Reference Id not supported for the provided application Id for EC Sign Keys.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.EC_SIGN_REFERENCE_ID_NOT_SUPPORTED.getErrorCode(),
					KeymanagerErrorConstant.EC_SIGN_REFERENCE_ID_NOT_SUPPORTED.getErrorMessage());
		}
    }
    
    private void validateResponseType(String responseType) {
		if (!keymanagerUtil.isValidResponseType(responseType)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, this.getClass().getSimpleName(), KeymanagerConstant.VALIDATE,
					"Invalid Response Object type provided for the key generation request.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(),
					KeymanagerErrorConstant.INVALID_REQUEST.getErrorMessage());
		}

        if (!responseType.toUpperCase().equals(KeymanagerConstant.REQUEST_TYPE_CERTIFICATE) && 
            !responseType.toUpperCase().equals(KeymanagerConstant.REQUEST_TYPE_CSR)) {
            LOGGER.error(KeymanagerConstant.SESSIONID, this.getClass().getSimpleName(), KeymanagerConstant.VALIDATE,
					"Invalid Response Object type provided for the key generation request. Allowed values are CSR/CERTIFICATE.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(),
					KeymanagerErrorConstant.INVALID_REQUEST.getErrorMessage() + " Allowed values are CSR/CERTIFICATE.");
        }
    }
    
}
