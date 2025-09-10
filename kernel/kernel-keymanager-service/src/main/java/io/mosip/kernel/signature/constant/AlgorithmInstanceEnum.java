package io.mosip.kernel.signature.constant;

import io.mosip.kernel.core.exception.IllegalArgumentException;
import lombok.Getter;
import org.jose4j.jws.AlgorithmIdentifiers;

@Getter
public enum AlgorithmInstanceEnum {
    RS256(AlgorithmIdentifiers.RSA_USING_SHA256, SignatureConstant.RS256_ALGORITHM),
    PS256(AlgorithmIdentifiers.RSA_PSS_USING_SHA256, SignatureConstant.RSA_PS256_SIGN_ALGORITHM_INSTANCE),
    ES256K1(AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256, SignatureConstant.EC256_ALGORITHM),
    ES256R1(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256, SignatureConstant.EC256_ALGORITHM),
    ED25519(AlgorithmIdentifiers.EDDSA, SignatureConstant.ED25519_ALGORITHM);

    private final String signAlgorithm;
    private final String algoInstance;

    AlgorithmInstanceEnum(String signAlgorithm, String algoInstance) {
        this.signAlgorithm = signAlgorithm;
        this.algoInstance = algoInstance;
    }

    public static String getAlgoInstance(String signAlgorithm) {
        for (AlgorithmInstanceEnum e : values()) {
            if (e.getSignAlgorithm().equals(signAlgorithm)) {
                return e.getAlgoInstance();
            }
        }
        throw new IllegalArgumentException(SignatureErrorCode.SIGN_ALGO_NOT_SUPPORTED.getErrorCode(),
                SignatureErrorCode.SIGN_ALGO_NOT_SUPPORTED.getErrorMessage() + signAlgorithm);
    }
}
