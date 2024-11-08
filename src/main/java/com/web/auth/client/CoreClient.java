package com.web.auth.client;

import com.web.auth.error.FeignCircuitBreakerErrorDecoder;
import com.web.auth.service.Core.ManagerDto;
import org.base.base.api.ApiResponseDto;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "core-service", configuration = FeignCircuitBreakerErrorDecoder.class, url = "${core-service-url}")
@Qualifier("CoreHttpClient")
public interface CoreClient extends HttpClient {

    @GetMapping("/api/manager/{managerId}")
    ApiResponseDto<ManagerDto> getManagerById(@PathVariable("managerId") String managerId);
}
