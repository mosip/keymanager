package io.mosip.kernel.keymanager.dto;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
public class CoseSignResponseDto {
    private String id;
    private String version;
    private LocalDateTime responsetime;
    private Map<String, Object> metadata;
    private CoseSignResponse response;
    private List<Error> errors = new ArrayList<>();

    @Data
    public static class CoseSignResponse {
        private String coseSignedData;
        private LocalDateTime timestamp;
    }

    @Data
    public static class Error {
        private String errorCode;
        private String message;
    }
} 
