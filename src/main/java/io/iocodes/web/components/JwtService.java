package io.iocodes.web.components;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Service
public class JwtService {

    @Value("${rsaPrivateKey}")
    private String rsaPrivateKey;
    @Value("${rsaPublicKey}")
    private String rsaPublicKey;

    public PrivateKey generatePrivateKey() {
        try {
            var keyBytes = Base64.getDecoder().decode(rsaPrivateKey);
            var privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public PublicKey generatePublicKey() {
        try {
            var keyBytes = Base64.getDecoder().decode(rsaPublicKey);
            var publicKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String generateJwtToken(String username) {
        long expirationDate = System.currentTimeMillis() + (24 * 3600 * 1000);
        return Jwts
            .builder()
            .header().type("JWT").and()
            .subject(username)
            .claim("type", "access_token")
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(expirationDate))
            .signWith(generatePrivateKey()).compact();
    }

    public String generateRefreshToken(String username) {
        long expirationDate = System.currentTimeMillis() + (7 * 24 * 3600 * 1000);
        return Jwts
           .builder()
            .header().type("JWT").and()
            .subject(username)
            .claim("type", "refresh_token")
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(expirationDate))
            .signWith(generatePrivateKey()).compact();
    }

    public Claims extractClaims(String token) {
        try {
            return Jwts.parser()
                .verifyWith(generatePublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Date extractExpiration(String token) {
        return extractClaims(token).getExpiration();
    }

    public String extractSubject(String token) {
        return extractClaims(token).getSubject();
    }

    public String extractTokenType(String token) {
        return (String) extractClaims(token).get("type");
    }

    public boolean validateToken(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }
}
