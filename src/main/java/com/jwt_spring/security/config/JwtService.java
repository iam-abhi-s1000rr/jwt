package com.jwt_spring.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service

public class JwtService {
    private static final String SECRECT_KEY="5A7234753777217A25432A462D4A614E645267556B58703273357638792F413F";
    public String extractUsername(String token/*jwt*/){

        return extractClaim(token,Claims::getSubject);
    }

    public String generateToken(Map<String,Object> extractClaim, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extractClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    //A claim is represented as a name-value pair that contains a Claim Name and a Claim Value.
    //here we are extracting claims because "claims in a JWT are encoded as a JSON objects"
    // JSON objects used as the payload of a JSON Web Signature (JWS) structure
    //mostly for WEB Encryption

    public <T>T extractClaim(String token, Function<Claims,T>claimResolver){
        final Claims claims=extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public Claims extractAllClaims(String token/*jwt*/){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                // signingkey is used to auto-decode the token while signing in
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // we dont have the signInKey() we need to create it
    private Key getSignKey() {
       byte[] keyBytes= Decoders.BASE64.decode(SECRECT_KEY);
       return Keys.hmacShaKeyFor(keyBytes);
    }
}
