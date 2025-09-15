package io.mosip.kernel.signature.constant;

import io.mosip.kernel.core.exception.IllegalArgumentException;
import io.mosip.kernel.keymanagerservice.constant.KeyReferenceIdConsts;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import lombok.Getter;
import org.jose4j.jws.AlgorithmIdentifiers;

@Getter
public enum SignatureAlgorithmIdentifyEnum {
    BLANK(SignatureConstant.BLANK, AlgorithmIdentifiers.RSA_USING_SHA256),
    REF(SignatureConstant.REF_ID_SIGN_CONST, AlgorithmIdentifiers.RSA_USING_SHA256),
    SECP256K1(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name(), AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256),
    SECP256R1(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name(), AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256),
    ED25519(KeyReferenceIdConsts.ED25519_SIGN.name(), AlgorithmIdentifiers.EDDSA);

    private final String referenceId;
    private final String algoIdent;

    SignatureAlgorithmIdentifyEnum(String referenceId, String algoIdent) {
        this.referenceId = referenceId;
        this.algoIdent = algoIdent;
    }

    public static String getAlgorithmIdentifier(String refId) {
        for (SignatureAlgorithmIdentifyEnum e : values()) {
            if (e.getReferenceId().equals(refId)) {
                return e.getAlgoIdent();
            }
        }
        throw new IllegalArgumentException(KeymanagerErrorConstant.REFERENCE_ID_NOT_SUPPORTED.getErrorCode(),
                KeymanagerErrorConstant.REFERENCE_ID_NOT_SUPPORTED.getErrorMessage() + refId);
    }
}
