package com.macrosol.security.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Component
public class JwtTokenUtil2 implements Serializable {

    static final String CLAIM_KEY_USERNAME = "sub";
    static final String CLAIM_KEY_CREATED = "iat";
    private static final long serialVersionUID = -3301605591108950415L;
    @SuppressFBWarnings(value = "SE_BAD_FIELD", justification = "It's okay here")
    private Clock clock = DefaultClock.INSTANCE;

    @Value("${jwt.secret}")
    private String secret; //private key

    @Value("${jwt.expiration}")
    private Long expiration; //expiration date

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

        //HEADER
        final Map<String, Object> header = new HashMap<>(2);
        header.put("typ", "MACHINE_TOKEN_KIND");
        header.put("alg", "workspaceId");

        //CLAIMS
        // iss: jwtproxy required claims - PMU client number
        claims.put(Claims.ISSUER, "wsmaster");
        // iat
        claims.put(Claims.ISSUED_AT, Instant.now().getEpochSecond());
        // jti: to ensure that each token is unique
        claims.put(Claims.ID, UUID.randomUUID().toString());
        //claims.put(Claims.AUDIENCE, workspaceId);
        //claims.put(Claims.EXPIRATION, Instant.now().plus(365, DAYS).getEpochSecond());
        //claims.put(Claims.NOT_BEFORE, -1); // always


        // clients data
        //claims.put(Constants.USER_ID_CLAIM, userId);
        //claims.put(Constants.USER_NAME_CLAIM, user.getName());
        //claims.put(Constants.WORKSPACE_ID_CLAIM, workspaceId);


        return doGenerateToken(claims, header, userDetails.getUsername());
    }

    /** Creates new token with given data. */
    /*private String createToken(String userId, String workspaceId) throws MachineTokenException {
        try {
            final PrivateKey privateKey =
                signatureKeyManager.getOrCreateKeyPair(workspaceId).getPrivate();
            final User user = userManager.getById(userId);
            final Map<string, object=""> header = new HashMap<>(2);
            header.put("kind", MACHINE_TOKEN_KIND);
            header.put("kid", workspaceId);
            final Map<string, object=""> claims = new HashMap<>();
            // to ensure that each token is unique
            claims.put(Claims.ID, UUID.randomUUID().toString());
            claims.put(Constants.USER_ID_CLAIM, userId);
            claims.put(Constants.USER_NAME_CLAIM, user.getName());
            claims.put(Constants.WORKSPACE_ID_CLAIM, workspaceId);
            // jwtproxy required claims
            claims.put(Claims.ISSUER, "wsmaster");
            claims.put(Claims.AUDIENCE, workspaceId);
            claims.put(Claims.EXPIRATION, Instant.now().plus(365, DAYS).getEpochSecond());
            claims.put(Claims.NOT_BEFORE, -1); // always
            claims.put(Claims.ISSUED_AT, Instant.now().getEpochSecond());
            final String token =
                Jwts.builder().setClaims(claims).setHeader(header).signWith(RS256, privateKey).compact();
            tokens.put(workspaceId, userId, token);
            return token;
        } catch (SignatureKeyManagerException | NotFoundException | ServerException ex) {
            throw new MachineTokenException(
                format(
                    "Failed to generate machine token for user '%s' and workspace '%s'. Cause: '%s'",
                    userId, workspaceId, ex.getMessage()),
                ex);
        }
    }*/

    private String doGenerateToken(Map<String, Object> claims, Map<String, Object> header, String subject) {
        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(createdDate);

        /*return Jwts.builder()
                .setHeader(header)
                .setClaims(claims)
                //.setId()
                //.setIssuer()
                //.setIssuedAt(createdDate) //iat
                //.setExpiration(expirationDate)
                //.signWith(RS256, privateKey)
                .signWith(SignatureAlgorithm.HS512, secret) //HMACHS512
                .compact();
         */

        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setIssuedAt(createdDate) //iat
            .setExpiration(expirationDate)
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
        return new Date(createdDate.getTime() + expiration * 1000);
    }
}
