package io.mosip.kernel.signature.service.impl;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import org.jose4j.jws.EcdsaUsingShaAlgorithm;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.service.SignatureProvider;

/**
 * 
 * @author Mahammed Taheer
 * @since 1.2.0
 *
 */
public class EC256SignatureProviderImpl implements SignatureProvider {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(EC256SignatureProviderImpl.class);

    @Override
    public String sign(PrivateKey privateKey, byte[] signData, String providerName) {
        
        try {
            Signature signatureObj = Signature.getInstance(SignatureConstant.EC256_ALGORITHM, providerName);
            signatureObj.initSign(privateKey, new SecureRandom());
            signatureObj.update(signData);
            byte[] signatureData = signatureObj.sign();
            byte[] derConcatnated = EcdsaUsingShaAlgorithm.convertDerToConcatenated(signatureData, SignatureConstant.EC256_SIGNATURE_LENGTH);
            return CryptoUtil.encodeToURLSafeBase64(derConcatnated);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | 
                    IOException | NoSuchProviderException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Error while signing the data.", e);
            throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(), 
                        SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
        }
    }
}
