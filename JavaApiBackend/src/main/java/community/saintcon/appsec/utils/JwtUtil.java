package community.saintcon.appsec.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Payload;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtUtil {

    private final String secret;

    public JwtUtil() throws IOException {
        this.secret = readSecretFromFile();
    }

    private String readSecretFromFile() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader("/run/secrets/app_secret"));
        return br.readLine();
    }

    public String generateToken(Long claimId, long expiryInMinutes, String prefix) {
        return createToken(prefix + "-" + claimId.toString(), expiryInMinutes);
    }

    public Long getValidatedClaimId(String token, String prefix) {
        if (!isTokenExpired(token)) {
            String subject = getClaimFromToken(token, Payload::getSubject);
            String[] parts = subject.split("-");
            if (!parts[0].equals(prefix) || parts.length < 2) {
                return null;
            }
            return Long.parseLong(parts[1]);
        }
        return null;
    }

    private Date extractExpiration(String token) {
        return getClaimFromToken(token, DecodedJWT::getExpiresAt);
    }

    private <T> T getClaimFromToken(String token, Function<DecodedJWT, T> claimsResolver) {
        final DecodedJWT jwt = decodeToken(token);
        return claimsResolver.apply(jwt);
    }

    private DecodedJWT decodeToken(String token) {
        return JWT.require(Algorithm.HMAC256(secret.getBytes())).build().verify(token);
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private String createToken(String subject, Long expiryInMinutes) {
        return JWT.create()
                .withSubject(subject)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + (expiryInMinutes * 60 * 1000)))
                .sign(Algorithm.HMAC256(secret.getBytes()));
    }

}
