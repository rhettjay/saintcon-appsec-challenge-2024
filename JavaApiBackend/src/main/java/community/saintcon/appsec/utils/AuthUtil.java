package community.saintcon.appsec.utils;

import community.saintcon.appsec.model.User;
import community.saintcon.appsec.model.UserWithPassword;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import java.util.Arrays;
import java.util.stream.Collectors;

@Component
public class AuthUtil {
    final static String AUTH_COOKIE_NAME = "auth";
    final static long AUTH_TOKEN_TTL = 60 * 24 * 7;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private DbService dbService;

    @Value("${spring.isProd}")
    private boolean isProd;

    public User getAuthenticatedUser(HttpServletRequest request) {
        Cookie authToken = WebUtils.getCookie(request, AUTH_COOKIE_NAME);
        if (authToken == null) {
            return null;
        }
        Long userId = jwtUtil.getValidatedClaimId(authToken.getValue(), "U");
        if (userId == null) {
            return null;
        }
        User user = dbService.getUser(userId);
        if (user.banned()) {
            return null;
        }
        return user;
    }

    public UserWithPassword getAuthenticatedUserWithPassword(HttpServletRequest request) {
        Cookie authToken = WebUtils.getCookie(request, AUTH_COOKIE_NAME);
        if (authToken == null) {
            return null;
        }
        Long userId = jwtUtil.getValidatedClaimId(authToken.getValue(), "U");
        if (userId == null) {
            return null;
        }
        return dbService.getUserWithPassword(userId);
    }

    public void setAuthenticatedUser(HttpServletResponse response, long userId) {
        final Cookie cookie = new Cookie(AUTH_COOKIE_NAME, jwtUtil.generateToken(userId, AUTH_TOKEN_TTL, "U"));
        cookie.setSecure(isProd);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(60 * 60 * 24 * 30);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
