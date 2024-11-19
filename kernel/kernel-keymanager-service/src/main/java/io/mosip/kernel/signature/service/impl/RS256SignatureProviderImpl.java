package io.mosip.kernel.signature.service.impl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.service.SignatureProvider;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;

/**
 * 
 * @author Mahammed Taheer
 * @since 1.2.0
 *
 */
public class RS256SignatureProviderImpl implements SignatureProvider {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(RS256SignatureProviderImpl.class);

    @Override
    public String sign(PrivateKey privateKey, byte[] signData, String providerName) {
        
        try {
            Signature signatureObj = Signature.getInstance(SignatureConstant.RS256_ALGORITHM, providerName);
            signatureObj.initSign(privateKey);
            signatureObj.update(signData);
            return CryptoUtil.encodeToURLSafeBase64(signatureObj.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Error while signing the data.");
            throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(), 
                        SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
        }
    }
}
