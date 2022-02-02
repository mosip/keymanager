package io.mosip.kernel.signature.service.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

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
public class PS256SIgnatureProviderImpl implements SignatureProvider {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(PS256SIgnatureProviderImpl.class);

    @Override
    public String sign(PrivateKey privateKey, byte[] signData, String providerName) {
        
        try {
            Signature signatureObj = Signature.getInstance(SignatureConstant.PS256_ALGORITHM, providerName);
            
            PSSParameterSpec pssParamSpec = new PSSParameterSpec(SignatureConstant.PSS_PARAM_SHA_256, SignatureConstant.PSS_PARAM_MGF1, 
                        MGF1ParameterSpec.SHA256, SignatureConstant.PSS_PARAM_SALT_LEN, SignatureConstant.PSS_PARAM_TF);
            signatureObj.setParameter(pssParamSpec);

            signatureObj.initSign(privateKey);
            signatureObj.update(signData);
            return CryptoUtil.encodeToURLSafeBase64(signatureObj.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Error while signing the data.");
            throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(), 
                        SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
        }
    }
}
