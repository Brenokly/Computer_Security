package com.ufersa.seguranca.util;

import java.security.Key;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

public class JwtService {

    private static final Key CHAVE = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRACAO = 300000;

    public static String gerarToken(String usuario, String role) {
        return Jwts.builder()
                .setSubject(usuario)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRACAO))
                .signWith(CHAVE)
                .compact();
    }

    public static Claims validarToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(CHAVE)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException | MalformedJwtException | UnsupportedJwtException | SignatureException | IllegalArgumentException e) {
            return null;
        }
    }
}
