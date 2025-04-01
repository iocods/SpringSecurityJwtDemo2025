package io.iocodes.web.controller;

import io.iocodes.web.dto.LoginDto;
import io.iocodes.web.dto.RegisterDto;
import io.iocodes.web.entity.User;
import io.iocodes.web.service.UserService;
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
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto loginDto, HttpServletResponse response) {
        var authenticationDetails = userService.authenticate(loginDto, response);
        if(authenticationDetails != null && !authenticationDetails.isEmpty()){
            return ResponseEntity.ok()
                    .header("Authorization", "Bearer " + authenticationDetails.get("access_token"))
                    .body((User) authenticationDetails.get("user"));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Username or Password");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        var accessToken = userService.refreshToken(request, response);
        if(accessToken != null)
            return ResponseEntity.ok()
                .header("Authorization", "Bearer " + accessToken)
                .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Refresh Token");
    }

    @PostMapping("/register")
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
