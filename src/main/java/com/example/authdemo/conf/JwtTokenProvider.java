package com.example.authdemo.conf;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@Log
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${jwt.public.key}")
    private String jwtSecret;

    public boolean validateToken(String token) {
        try {

            _getClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.severe("Token expired, details: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.severe("Unsupported jwt, details: " + e.getMessage());
        } catch (MalformedJwtException e) {
            log.severe("Malformed jwt, details: " + e.getMessage());
        } catch (SignatureException e) {
            log.severe("SignatureException jwt, details: " + e.getMessage());
        } catch (Exception e) {
            log.severe("invalid token, details: " + e.getMessage());
        }
        return false;
    }

    public Claims getClaims(String token) {
        try {
            return _getClaims(token);
        } catch (Exception e) {
            log.severe("Can't extract claims from token");
            throw new RuntimeException("Can't extract claims from token");
        }
    }



    private Claims _getClaims(String token) throws Exception {
        PublicKey publicKey = decodePublicKey(pemToDer(jwtSecret));
        return Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token).getBody();
    }

    private byte[] pemToDer(String pem) {
        return Base64.getDecoder().decode(stripBeginEnd(pem).getBytes(StandardCharsets.UTF_8));
    }

    private String stripBeginEnd(String pem) {
        String stripped = pem.replaceAll("-----BEGIN (.*)-----", "");
        stripped = stripped.replaceAll("-----END (.*)----", "");
        stripped = stripped.replaceAll("\r\n", "");
        stripped = stripped.replaceAll("\n", "");

        return stripped.trim();
    }

    private PublicKey decodePublicKey(byte[] der) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);

    }

    public Object getValueFromToken(String searchField, Class cl, HttpServletRequest request) {
        String token = request.getHeader("Authorization").replaceAll("Bearer ", "");
        Claims claims = getClaims(token);
        return claims.get(searchField, cl);
    }

    public String getUserId(HttpServletRequest request) {
        String email = (String) getValueFromToken("email", String.class, request);
        return email.replaceAll("@dar.kz", "").replaceAll("@index.com", "");
    }




}
