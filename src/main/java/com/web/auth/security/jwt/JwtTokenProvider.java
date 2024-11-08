package com.web.auth.security.jwt;

import com.web.auth.constants.SecurityConstants;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {

    private static long accessTokenExp;
    private static long refreshTokenExp;

    @Value("${security.access-token-exp:}")
    private void setValue1(long value) { accessTokenExp = value; }

    @Value("${security.refresh-token-exp:}")
    private void setValue2(long value) { refreshTokenExp = value; }

    private static ConcurrentMap<String, String> tokenMap = new ConcurrentHashMap<>();

    private static String createToken(String userId, String username, List<String> roles, long expiration) {
        byte[] signingKey = SecurityConstants.JWT_SECRET.getBytes();

        String token = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS512) // 토큰 서명에 사용할 알고리즘
                .setHeaderParam("typ", SecurityConstants.TOKEN_TYPE) // 토큰 헤더의 타입 설정 (보통 JWT)
                .setIssuer(SecurityConstants.TOKEN_ISSUER) // 토큰 발행자 설정
                .setAudience(SecurityConstants.TOKEN_AUDIENCE) // 토큰 대상자 설정
                .setId(userId) // 토큰 식별자
                .setSubject(username)
                .setExpiration(new Date(expiration))
                .claim("rol", roles)
                .compact();
        log.info("Token created: {}, {}", username, token);

        return token;
    }

    public Map<String, String> getAuthInfoByToken(String token) {
        try {
            token = token.replace("Bearer ", ""); // 토큰 앞에 붙은 "Bearer " 제거

            byte[] signingKey = SecurityConstants.JWT_SECRET.getBytes();

            Jws<Claims> parsedToken = Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(signingKey))
                    .build()
                    .parseClaimsJws(token);

            String userId = parsedToken.getBody().getId();

            Collection<GrantedAuthority> authorities = ((List<?>) parsedToken.getBody()
                    .get("rol"))
                    .stream()
                    .map(authority -> new SimpleGrantedAuthority((String) authority))
                    .collect(Collectors.toList());

            String roles = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));

            Date expirationDate = parsedToken.getBody().getExpiration();
            String expiration = expirationDate != null ? String.valueOf(expirationDate.getTime()) : null;

            Map<String, String> result = new HashMap<>();
            result.put("userId", userId);
            result.put("roles", roles);
            result.put("expiration", expiration);
            return result;
        }catch (RuntimeException e) {
            return new HashMap<String, String>();
        }
    }

    // 엑세스 토큰 발급
    public static String doGenerateAccessToken(String userId, String username, List<String> roles) {
        long exp = System.currentTimeMillis() + accessTokenExp;
        String token = createToken(userId, username, roles, exp);

        log.info("Create access-token : {}, {}, {}", userId, username, token);
        tokenMap.put(userId, token);
        return token;
    }

    // Refresh 토큰 발급
    public static String doGenerateRefreshToken(String userId, String username, List<String> roles) {
        long exp = System.currentTimeMillis() + refreshTokenExp ;
        String token = createToken(userId, username, roles, exp);
        log.info("Create refresh-token : {}, {}, {}", userId, username, token);
        return token;
    }

    // 잘못된 토큰일 경우
    public static void invalidateToken(String userId) {
        tokenMap.remove(userId);
    }

    // 토큰 만료
    private static void expireTokenByVal(String token) {
        Optional<String> userId = tokenMap.keySet()
                .stream()
                .filter(key -> tokenMap.get(key).equals(token))
                .findFirst();

        userId.ifPresent(JwtTokenProvider::expireToken);
    }

    // 만료된 토큰일 경우
    private static void expireToken(String userId) {
        tokenMap.remove(userId);
    }

    public static UsernamePasswordAuthenticationToken getAuthentication(String token){
        // 토큰이 존재하는지 확인
        // StringUtils를 사용하면 Null 안전성을 줄 수 있다. 일반 .isEmpty를 사용하면 Null일 때 NullException이 발생한다.
        if(StringUtils.isNoneEmpty(token) && token.startsWith(SecurityConstants.TOKEN_PREFIX)){
            // 앞의 Bearer 제거
            token = token.replace(SecurityConstants.TOKEN_PREFIX, "");
        }

        try {
            byte[] signingKey = SecurityConstants.JWT_SECRET.getBytes();

            Jws<Claims> parsedToken = Jwts.parser()
                    .setSigningKey(signingKey)
                    .build()
                    .parseSignedClaims(token);

            String userId = parsedToken.getBody().getId();

            Collection<GrantedAuthority> authorities = ((List<?>) parsedToken.getBody()
                    .get("rol"))
                    .stream()
                    .map(authority -> new SimpleGrantedAuthority((String) authority))
                    .collect(Collectors.toList());

            if (StringUtils.isNotEmpty(userId)) {
                return new UsernamePasswordAuthenticationToken(userId, null, authorities);
            }
        } catch (ExpiredJwtException exception){
            log.warn("토큰이 만료되었어요");
        }catch (UnsupportedJwtException exception) {
            log.warn("Request to parse unsupported JWT : {} failed : {}", token, exception.getMessage());
        } catch (MalformedJwtException exception) {
            log.warn("Request to parse invalid JWT : {} failed : {}", token, exception.getMessage());
        } catch (IllegalArgumentException exception) {
            log.warn("Request to parse empty or null JWT : {} failed : {}", token, exception.getMessage());
        } catch (Exception exception) {
            log.error(exception.getMessage(), exception);
        }
        return null;
    }
}
