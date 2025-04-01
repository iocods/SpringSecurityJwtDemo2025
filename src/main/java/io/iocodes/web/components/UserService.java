package io.iocodes.web.components;

import jakarta.servlet.http.HttpServletRequest;
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

    public Map<String, Object> authenticate(LoginDto loginDto) {
        User user = (User) userDetailsService.loadUserByUsername(loginDto.getUsername());
        if(user != null) {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));
            String jwtToken = jwtService.generateJwtToken(user.getUsername());
            String refreshToken = jwtService.generateRefreshToken(user.getUsername());
            return Map.of("access_token", jwtToken, "refresh_token", refreshToken, "user", user);
        }
        return Map.of();
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
}
