package com.ufersa.seguranca.util;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

/**
 * Serviço de Tokens JWT (JSON Web Token).
 * Segurança: Utiliza uma chave mestra dinâmica (gerada na inicialização do Auth)
 * e sincronizada via rede protegida por RSA, evitando chaves hardcoded no código.
 */

public class JwtService {

    private static Key CHAVE;
    private static final long EXPIRACAO = 300000; // 5 minutos

    // Método chamado pelo AUTH para criar a chave MESTRA aleatória
    public static String inicializarChaveAleatoria() {
        byte[] segredo = new byte[32]; // 256 bits
        new SecureRandom().nextBytes(segredo);
        CHAVE = Keys.hmacShaKeyFor(segredo);
        return Base64.getEncoder().encodeToString(segredo);
    }

    // Método chamado pela BORDA/CLOUD para setar a chave recebida
    public static void setChaveMestra(String segredoBase64) {
        byte[] segredo = Base64.getDecoder().decode(segredoBase64);
        CHAVE = Keys.hmacShaKeyFor(segredo);
    }

    public static String gerarToken(String usuario, String role) {
        if (CHAVE == null) {
            throw new RuntimeException("Chave JWT nao inicializada!");
        }
        return Jwts.builder()
                .setSubject(usuario)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRACAO))
                .signWith(CHAVE)
                .compact();
    }

    public static Claims validarToken(String token) {
        if (CHAVE == null) {
            return null;
        }
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
