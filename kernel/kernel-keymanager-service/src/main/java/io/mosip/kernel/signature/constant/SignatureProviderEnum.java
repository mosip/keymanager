package io.mosip.kernel.signature.constant;

import io.mosip.kernel.core.exception.IllegalArgumentException;
import io.mosip.kernel.signature.service.SignatureProvider;
import io.mosip.kernel.signature.service.impl.EC256SignatureProviderImpl;
import io.mosip.kernel.signature.service.impl.Ed25519SignatureProviderImpl;
import io.mosip.kernel.signature.service.impl.PS256SIgnatureProviderImpl;
import io.mosip.kernel.signature.service.impl.RS256SignatureProviderImpl;
import lombok.Getter;

@Getter
public enum SignatureProviderEnum {
    PS256(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST, new PS256SIgnatureProviderImpl()),
    RS256(SignatureConstant.JWS_RS256_SIGN_ALGO_CONST, new RS256SignatureProviderImpl()),
    ES256(SignatureConstant.JWS_ES256_SIGN_ALGO_CONST, new EC256SignatureProviderImpl()),
    ES256K(SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST, new EC256SignatureProviderImpl()),
    EDDSA(SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST, new Ed25519SignatureProviderImpl());

    private final String algo;
    private final SignatureProvider provider;

    SignatureProviderEnum(String algo, SignatureProvider provider) {
        this.algo = algo;
        this.provider = provider;
    }

    public static SignatureProvider getSignatureProvider(String algo) {
        for (SignatureProviderEnum e : values()) {
            if (e.getAlgo().equals(algo)) {
                return e.getProvider();
            }
        }
        throw new IllegalArgumentException(SignatureErrorCode.SIGN_ALGO_NOT_SUPPORTED.getErrorCode(),
                SignatureErrorCode.SIGN_ALGO_NOT_SUPPORTED.getErrorMessage() + algo);
    }

}
