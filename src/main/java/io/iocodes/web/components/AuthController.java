package io.iocodes.web.components;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    @RequestMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto loginDto, HttpServletResponse response) {
        var authenticationDetails = userService.authenticate(loginDto);
        if(authenticationDetails != null && !authenticationDetails.isEmpty()){
            var refreshToken = authenticationDetails.get("refresh_token");
            Cookie refreshTokenCookie = new Cookie("refresh_token", (String) refreshToken);
            refreshTokenCookie.setHttpOnly(true);  // Prevents JavaScript access (XSS protection)
            refreshTokenCookie.setSecure(true);    // Ensures HTTPS only (important for production)
            refreshTokenCookie.setPath("/");       // Available for the entire application
            refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days expiration

            // Add the cookie to the response
            response.addCookie(refreshTokenCookie);
            return ResponseEntity.ok()
                    .header("Authorization", "Bearer " + authenticationDetails.get("access_token"))
                    .body((User) authenticationDetails.get("user"));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Username or Password");
    }

    @RequestMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterDto registerDto) {
        var user = userService.register(registerDto);
        return ResponseEntity.ok(user);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        userService.logout(request);
        return ResponseEntity.ok("Logged Out Successfully");
    }
}
