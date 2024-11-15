package com.bist.backendmodule.helpers;

import com.bist.backendmodule.exceptions.*;
import com.bist.backendmodule.modules.group.models.Group;
import com.bist.backendmodule.modules.permission.models.Permission;
import com.bist.backendmodule.security.models.TokenRequest;
import com.bist.backendmodule.security.models.TokenResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Utility class for generating and validating JWT tokens.
 */
public class JwtUtility {
    private static final SecretKey SIGNING_KEY = KeyGenUtil.fetchGeneratedKey();
    private static final long TEN_DAYS_EXPIRATION_TIME = 864_000_000;

    /**
     * Generates a JWT token based on the provided TokenRequest.
     *
     * @param request The request containing user details
     * @return A TokenResponse containing the username and generated token
     */
    public static TokenResponse createJwtToken(TokenRequest request) {
        String jwt = Jwts.builder()
                .claim("sub", request.getUsername())
                .claim("id", request.getUserId())
                .claim("roles", request.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .claim("permissions", request.getPermissions().stream().map(Permission::getAuthority).collect(Collectors.toList()))
                .claim("groups", request.getGroups().stream().map(Group::getName).collect(Collectors.toList()))
                .claim("iat", new Date(System.currentTimeMillis()))
                .claim("exp", new Date(System.currentTimeMillis() + TEN_DAYS_EXPIRATION_TIME))
                .signWith(SIGNING_KEY)
                .compact();

        return new TokenResponse(request.getUsername(), jwt);
    }

    /**
     * Retrieves all claims from the given JWT token.
     *
     * @param jwtToken The JWT token
     * @return The claims contained in the token
     * @throws InvalidTokenSignatureException if the token signature is invalid
     * @throws TokenValidationException       if the token validation fails
     */
    public static Claims extractClaimsFromToken(String jwtToken) {
        try {
            return Jwts.parser()
                    .verifyWith(SIGNING_KEY)
                    .build()
                    .parseSignedClaims(jwtToken)
                    .getPayload();
        } catch (SignatureException signatureEx) {
            throw new InvalidTokenSignatureException("Invalid token signature.", signatureEx, JwtUtility.class);
        } catch (Exception generalEx) {
            throw new TokenValidationException("Token validation failed.", generalEx, JwtUtility.class);
        }
    }

    /**
     * Extracts the username from the JWT token.
     *
     * @param jwtToken The JWT token
     * @return The username
     */
    public static String extractUsername(String jwtToken) {
        return extractClaimsFromToken(jwtToken).get("sub", String.class);
    }

    /**
     * Checks if the JWT token is expired.
     *
     * @param jwtToken The JWT token
     * @return True if the token is expired, false otherwise
     */
    public static boolean hasTokenExpired(String jwtToken) {
        try {
            Date expDate = extractClaimsFromToken(jwtToken).getExpiration();
            return expDate.before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Extracts the authorities (roles and permissions) from the JWT token.
     *
     * @param jwtToken The JWT token
     * @return A list of GrantedAuthority
     */
    public static List<GrantedAuthority> extractAuthorities(String jwtToken) {
        List<String> userRoles = extractRolesFromToken(jwtToken);
        List<String> userPermissions = extractPermissionsFromToken(jwtToken);
        return Stream.concat(userRoles.stream(), userPermissions.stream())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    /**
     * Extracts the roles from the JWT token.
     *
     * @param jwtToken The JWT token
     * @return A list of roles
     * @throws InvalidRolesFormatException if the roles format is invalid
     */
    private static List<String> extractRolesFromToken(String jwtToken) {
        Claims jwtClaims = extractClaimsFromToken(jwtToken);
        Object rolesData = jwtClaims.get("roles");
        if (rolesData instanceof List<?>) {
            return ((List<?>) rolesData).stream()
                    .filter(item -> item instanceof String)
                    .map(item -> (String) item)
                    .toList();
        }
        throw new InvalidRolesFormatException("Invalid roles format.", JwtUtility.class);
    }

    /**
     * Extracts the permissions from the JWT token.
     *
     * @param jwtToken The JWT token
     * @return A list of permissions
     * @throws InvalidPermissionsFormatException if the permissions format is invalid
     */
    private static List<String> extractPermissionsFromToken(String jwtToken) {
        Claims jwtClaims = extractClaimsFromToken(jwtToken);
        Object permissionsData = jwtClaims.get("permissions");
        if (permissionsData instanceof List<?>) {
            return ((List<?>) permissionsData).stream()
                    .filter(item -> item instanceof String)
                    .map(item -> (String) item)
                    .toList();
        }
        throw new InvalidPermissionsFormatException("Invalid permissions format.", JwtUtility.class);
    }

    /**
     * Extracts the groups from the JWT token.
     *
     * @param jwtToken The JWT token
     * @return A list of groups
     * @throws InvalidGroupsFormatException if the groups format is invalid
     */
    private static List<String> extractGroupsFromToken(String jwtToken) {
        Claims jwtClaims = extractClaimsFromToken(jwtToken);
        Object groupsData = jwtClaims.get("groups");
        if (groupsData instanceof List<?>) {
            return ((List<?>) groupsData).stream()
                    .filter(item -> item instanceof String)
                    .map(item -> (String) item)
                    .toList();
        }
        throw new InvalidGroupsFormatException("Invalid groups format.", JwtUtility.class);
    }

    /**
     * Validates the JWT token against the provided username.
     *
     * @param jwtToken The JWT token
     * @param username The username to validate against
     * @return True if the token is valid and not expired, false otherwise
     */
    public static boolean validateJwtToken(String jwtToken, String username) {
        final String extractedUsername = extractUsername(jwtToken);
        return (extractedUsername.equals(username) && !hasTokenExpired(jwtToken));
    }
}
