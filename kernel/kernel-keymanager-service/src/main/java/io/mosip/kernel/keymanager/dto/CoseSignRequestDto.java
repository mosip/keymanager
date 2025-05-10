package io.mosip.kernel.keymanager.dto;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.Map;

@Data
public class CoseSignRequestDto {
    private String id;
    private String version;
    private LocalDateTime requesttime;
    private Map<String, Object> metadata;
    private CoseSignRequest request;

    @Data
    public static class CoseSignRequest {
        private String cosePayload;
        private String applicationId;
        private String referenceId;
        private String coseProtectedHeader;
        private String coseUnprotectedHeader;
    }
} 
