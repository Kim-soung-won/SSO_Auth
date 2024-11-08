package com.web.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.web.auth.client.CoreClient;
import com.web.auth.security.jwt.JwtTokenProvider;
import com.web.auth.service.Core.ManagerDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {

    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    private final CoreClient coreClient;

    public String encode(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {

            ManagerDto dto  = coreClient.getManagerById(username).getData();
            if(dto==null){
                throw new UsernameNotFoundException("User not found : " + username);
            }

            User.UserBuilder builder = User.withUsername(dto.getUsername());
            builder.username(dto.getUsername());
            builder.password(dto.getPassword());
            builder.roles(String.valueOf(dto.getRoleId()));
            builder.disabled(!dto.isEnabled());
            return new CustomManagerDetails(builder.build(), dto);
        } catch (NoSuchElementException e) {
            log.error("Username(id) not found. username(id) : {}", username);
            throw new UsernameNotFoundException("User not found");
        }
    }
}
