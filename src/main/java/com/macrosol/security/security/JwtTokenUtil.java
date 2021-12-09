package com.macrosol.security.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenUtil implements Serializable {

    static final String CLAIM_KEY_USERNAME = "sub";
    static final String CLAIM_KEY_CREATED = "iat";
    private static final long serialVersionUID = -3301605591108950415L;
    @SuppressFBWarnings(value = "SE_BAD_FIELD", justification = "It's okay here")
    private Clock clock = DefaultClock.INSTANCE;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
            .setSigningKey(secret)
            .parseClaimsJws(token)
            .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(clock.now());
    }

    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    private Boolean ignoreTokenExpiration(String token) {
        // here you specify tokens, for that the expiration is ignored
        return false;
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        final Map<String, Object> header = new HashMap<>(2);
        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(createdDate);

        //CLAIMS
       // iss: jwtproxy required claims - PMU client number
        String iss = "Numero PMU client";
        claims.put(Claims.ISSUER, "751293978");
        // iat
        long iat = Instant.now().getEpochSecond();
        claims.put(Claims.ISSUED_AT, 1636560982);
        // jti: to ensure that each token is unique
        String jti = UUID.randomUUID().toString();
        claims.put(Claims.ID,  "b0336bf096f8ba14b61a75aa36388aab");

        //claims.put(Claims.AUDIENCE, workspaceId);
        //claims.put(Claims.EXPIRATION, Instant.now().plus(365, DAYS).getEpochSecond());
        //claims.put(Claims.NOT_BEFORE, -1); // always

        claims.put("firstname", "Henry");
        claims.put("lastname", "Dupont");
        claims.put("email", "test.pmu@exemple.fr");
        claims.put("role", "client2010");
        claims.put("custom_field_1", "2010");
        claims.put("custom_field_2", "01/01/1990");
        claims.put("custom_field_3", "1");
        claims.put("custom_field_4", "Mr");

        //HEADER
        header.put("typ", "JWT");
        header.put("alg", "HS512");

        return doGenerateToken(claims, header, userDetails.getUsername());
    }

    private String doGenerateToken(Map<String, Object> claims, Map<String, Object> header, String subject) {
        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(createdDate);

        /*return Jwts.builder()
            .setClaims(claims)
            .setHeader(header)
            .setSubject(subject)
            .setIssuer("751293978") //iss
            .setIssuedAt(createdDate) //iat
            .setId("b0336bf096f8ba14b61a75aa36388aab")
            .setExpiration(expirationDate)
            .signWith(SignatureAlgorithm.HS512, secret) //HMACHS512
            .compact();*/

        return Jwts.builder()
            .setClaims(claims)
            .setHeader(header)
            //.setSubject(subject)
            //.setIssuedAt("1636560982") //iat
            //.setExpiration(expirationDate)
            .signWith(SignatureAlgorithm.HS512, secret) //HMACHS512
            .compact();
    }

    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getIssuedAtDateFromToken(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
            && (!isTokenExpired(token) || ignoreTokenExpiration(token));
    }

    public String refreshToken(String token) {
        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(createdDate);

        final Claims claims = getAllClaimsFromToken(token);
        claims.setIssuedAt(createdDate);
        claims.setExpiration(expirationDate);

        return Jwts.builder()
            .setClaims(claims)
            .signWith(SignatureAlgorithm.HS512, secret)
            .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        JwtUser user = (JwtUser) userDetails;
        final String username = getUsernameFromToken(token);
        final Date created = getIssuedAtDateFromToken(token);
        //final Date expiration = getExpirationDateFromToken(token);
        return (
            username.equals(user.getUsername())
                && !isTokenExpired(token)
                && !isCreatedBeforeLastPasswordReset(created, user.getLastPasswordResetDate())
        );
    }

    private Date calculateExpirationDate(Date createdDate) {
        return new Date(createdDate.getTime() + expiration * 1000 * 1000);
    }
}
