package io.mosip.kernel.keymanager.controller;

import io.mosip.kernel.keymanager.dto.CoseSignRequestDto;
import io.mosip.kernel.keymanager.dto.CoseSignResponseDto;
import io.mosip.kernel.keymanager.service.CoseSignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/keymanager")
public class CoseSignController {

    @Autowired
    private CoseSignService coseSignService;

    @PostMapping("/coseSign")
    public ResponseEntity<CoseSignResponseDto> signCose(@RequestBody CoseSignRequestDto request) {
        CoseSignResponseDto response = coseSignService.signCose(request);
        return ResponseEntity.ok(response);
    }
} 
