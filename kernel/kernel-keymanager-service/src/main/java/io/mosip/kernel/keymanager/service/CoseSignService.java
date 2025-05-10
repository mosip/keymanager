package io.mosip.kernel.keymanager.service;

import io.mosip.kernel.keymanager.dto.CoseSignRequestDto;
import io.mosip.kernel.keymanager.dto.CoseSignResponseDto;

public interface CoseSignService {
    CoseSignResponseDto signCose(CoseSignRequestDto request);
} 
