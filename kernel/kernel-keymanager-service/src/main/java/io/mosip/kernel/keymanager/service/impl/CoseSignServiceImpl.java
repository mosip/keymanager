package io.mosip.kernel.keymanager.service.impl;

import com.upokecenter.cbor.CBORObject;
import io.mosip.kernel.keymanager.dto.CoseSignRequestDto;
import io.mosip.kernel.keymanager.dto.CoseSignResponseDto;
import io.mosip.kernel.keymanager.service.CoseSignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;

@Service
public class CoseSignServiceImpl implements CoseSignService {

    @Autowired
    private KeyManagerService keyManagerService;

    @Override
    public CoseSignResponseDto signCose(CoseSignRequestDto request) {
        CoseSignResponseDto response = new CoseSignResponseDto();
        response.setId(request.getId());
        response.setVersion(request.getVersion());
        response.setResponsetime(LocalDateTime.now());
        response.setMetadata(new HashMap<>());

        try {
            // Validate request
            validateRequest(request);

            // Decode Base64URL encoded fields
            byte[] payload = Base64.getUrlDecoder().decode(request.getRequest().getCosePayload());
            byte[] protectedHeader = Base64.getUrlDecoder().decode(request.getRequest().getCoseProtectedHeader());
            byte[] unprotectedHeader = Base64.getUrlDecoder().decode(request.getRequest().getCoseUnprotectedHeader());

            // Parse CBOR headers
            CBORObject protectedHeaderObj = CBORObject.DecodeFromBytes(protectedHeader);
            CBORObject unprotectedHeaderObj = CBORObject.DecodeFromBytes(unprotectedHeader);

            // Validate headers
            validateHeaders(protectedHeaderObj, unprotectedHeaderObj);

            // Get key ID and algorithm from headers
            String kid = protectedHeaderObj.get(CBORObject.FromObject(4)).AsString(); // 4 is the label for kid
            int alg = protectedHeaderObj.get(CBORObject.FromObject(1)).AsInt32(); // 1 is the label for alg

            // Get private key from key manager
            PrivateKey privateKey = keyManagerService.getPrivateKey(kid);

            // Create Sig_structure
            CBORObject sigStructure = CBORObject.NewArray();
            sigStructure.Add("Signature1"); // context
            sigStructure.Add(protectedHeader); // body_protected
            sigStructure.Add(new byte[0]); // external_aad (empty for now)
            sigStructure.Add(payload); // payload

            // Sign the structure
            byte[] signature = signCoseSign1(sigStructure.EncodeToBytes(), privateKey, alg);

            // Create COSE_Sign1 structure
            CBORObject coseSign1 = CBORObject.NewArray();
            coseSign1.Add(protectedHeader);
            coseSign1.Add(unprotectedHeaderObj);
            coseSign1.Add(payload);
            coseSign1.Add(signature);

            // Encode the final structure
            String coseSignedData = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(coseSign1.EncodeToBytes());

            // Set response
            CoseSignResponseDto.CoseSignResponse responseData = new CoseSignResponseDto.CoseSignResponse();
            responseData.setCoseSignedData(coseSignedData);
            responseData.setTimestamp(LocalDateTime.now());
            response.setResponse(responseData);

        } catch (Exception e) {
            CoseSignResponseDto.Error error = new CoseSignResponseDto.Error();
            error.setErrorCode("KER-COS-001");
            error.setMessage("Failed to sign COSE data: " + e.getMessage());
            response.getErrors().add(error);
        }

        return response;
    }

    private void validateRequest(CoseSignRequestDto request) {
        if (request == null || request.getRequest() == null) {
            throw new IllegalArgumentException("Request or request body is null");
        }

        if (request.getRequest().getCosePayload() == null || request.getRequest().getCosePayload().isEmpty()) {
            throw new IllegalArgumentException("COSE payload is required");
        }

        if (request.getRequest().getCoseProtectedHeader() == null || request.getRequest().getCoseProtectedHeader().isEmpty()) {
            throw new IllegalArgumentException("COSE protected header is required");
        }

        if (request.getRequest().getCoseUnprotectedHeader() == null || request.getRequest().getCoseUnprotectedHeader().isEmpty()) {
            throw new IllegalArgumentException("COSE unprotected header is required");
        }

        if (request.getRequest().getApplicationId() == null || request.getRequest().getApplicationId().isEmpty()) {
            throw new IllegalArgumentException("Application ID is required");
        }

        if (request.getRequest().getReferenceId() == null || request.getRequest().getReferenceId().isEmpty()) {
            throw new IllegalArgumentException("Reference ID is required");
        }
    }

    private void validateHeaders(CBORObject protectedHeader, CBORObject unprotectedHeader) {
        // Check for required header fields
        if (!protectedHeader.ContainsKey(CBORObject.FromObject(1))) {
            throw new IllegalArgumentException("Algorithm (alg) is required in protected header");
        }

        if (!protectedHeader.ContainsKey(CBORObject.FromObject(4))) {
            throw new IllegalArgumentException("Key ID (kid) is required in protected header");
        }

        // Validate algorithm
        int alg = protectedHeader.get(CBORObject.FromObject(1)).AsInt32();
        if (!isValidAlgorithm(alg)) {
            throw new IllegalArgumentException("Unsupported algorithm: " + alg);
        }
    }

    private boolean isValidAlgorithm(int alg) {
        return alg == -7 || // ES256
               alg == -35 || // ES384
               alg == -36 || // ES512
               alg == -37;   // EdDSA
    }

    private byte[] signCoseSign1(byte[] data, PrivateKey privateKey, int alg) throws Exception {
        Signature signature;
        
        // Select signature algorithm based on COSE algorithm identifier
        switch (alg) {
            case -7: // ES256
                signature = Signature.getInstance("SHA256withECDSA");
                break;
            case -35: // ES384
                signature = Signature.getInstance("SHA384withECDSA");
                break;
            case -36: // ES512
                signature = Signature.getInstance("SHA512withECDSA");
                break;
            case -37: // EdDSA
                signature = Signature.getInstance("EdDSA");
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + alg);
        }

        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
} 
