package io.iocodes.web.components;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final JwtService jwtService;
    private final RedisService redisService;
    private final UserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Map<String, Object> authenticate(LoginDto loginDto, HttpServletResponse response) {
        User user = (User) userDetailsService.loadUserByUsername(loginDto.getUsername());
        if(user != null) {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));
            String jwtToken = jwtService.generateJwtToken(user.getUsername());
            String refreshToken = jwtService.generateRefreshToken(user.getUsername());
            Cookie refreshTokenCookie = getRefreshTokenCookie(refreshToken);
            // Add the cookie to the response
            response.addCookie(refreshTokenCookie);
            return Map.of("access_token", jwtToken,  "user", user);
        }
        return Map.of();
    }
    public String refreshToken(HttpServletRequest request, HttpServletResponse response) {
        var refreshTokenCookie = Arrays.stream(request.getCookies()).filter(cookie -> cookie.getName().equals("refresh_token")).findFirst().orElseThrow();
        var token = refreshTokenCookie.getValue();
        if(token != null) {
            if(jwtService.validateToken(token)) {
                var username = jwtService.extractSubject(token);
                String jwtToken = jwtService.generateJwtToken(username);
                String refreshToken = jwtService.generateRefreshToken(username);
                refreshTokenCookie = getRefreshTokenCookie(refreshToken);
                // Add the cookie to the response
                response.addCookie(refreshTokenCookie);
                return jwtToken;
            }
        }
        return null;
    }

    public User register(RegisterDto registerDto) {
        User user = User.builder()
            .username(registerDto.getUsername())
            .password(passwordEncoder.encode(registerDto.getPassword()))
            .roles(List.of("ROLE_USER"))
            .build();
        return userRepository.save(user);
    }

    public void logout(HttpServletRequest request) {
        var refreshTokenCookie = Arrays.stream(request.getCookies()).filter(cookie -> cookie.getName().equals("refresh_token")).findFirst().orElseThrow();
        var token = request.getHeader("Authorization").substring(7);
        log.info("Token value from request: {}", token);
        invalidateToken(token);
        invalidateToken(refreshTokenCookie.getValue());
    }

    private void invalidateToken(String token) {
        long expirationTimeInMilliseconds = jwtService.extractExpiration(token).getTime() - System.currentTimeMillis();
        if(expirationTimeInMilliseconds > 0)
            redisService.setTokenWithTTL(token, "blacklisted", expirationTimeInMilliseconds, TimeUnit.MILLISECONDS);
    }

    private Cookie getRefreshTokenCookie(String token) {
        Cookie refreshTokenCookie = new Cookie("refresh_token", (String) token);
        refreshTokenCookie.setHttpOnly(true);  // Prevents JavaScript access (XSS protection)
        refreshTokenCookie.setSecure(true);    // Ensures HTTPS only (important for production)
        refreshTokenCookie.setPath("/");       // Available for the entire application
        refreshTokenCookie.setMaxAge((int) (jwtService.extractExpiration(token).getTime() - System.currentTimeMillis())/1000); // Set to the remaining TTL of the token.
        return refreshTokenCookie;
    }
}
