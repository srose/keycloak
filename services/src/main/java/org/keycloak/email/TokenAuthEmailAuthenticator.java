package org.keycloak.email;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.MessagingException;
import jakarta.mail.Transport;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.vault.VaultStringSecret;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class TokenAuthEmailAuthenticator implements EmailAuthenticator {

    private static final Logger logger = Logger.getLogger(TokenAuthEmailAuthenticator.class);

    private final Map<String, TokenAuthEmailAuthenticator.TokenStoreEntry> tokenStore = new ConcurrentHashMap<>();

    @Override
    public void connect(KeycloakSession session, Map<String, String> config, Transport transport) throws EmailException {
        try {
            var token = gatherValidToken(session, config);
            transport.connect(config.get("user"), token);
        } catch (AuthenticationFailedException e) {
            this.tokenStore.remove(session.getContext().getRealm().getId());
            var token = gatherValidToken(session, config);
            try {
                transport.connect(config.get("user"), token);
            } catch (MessagingException ex) {
                throw new EmailException("Retry after AuthenticationFailed failed", ex);
            }
        } catch (MessagingException e) {
            throw new EmailException("Connect failed", e);
        }
    }

    private String gatherValidToken(KeycloakSession session, Map<String, String> config) throws EmailException {
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(config.get("authTokenClientSecret"))) {
            String authTokenClientSecret = vaultStringSecret.get().orElse(config.get("authTokenClientSecret"));
            String authTokenUrl = config.get("authTokenUrl");
            String authTokenClientId = config.get("authTokenClientId");
            String authTokenScope = config.get("authTokenScope");
            int authTokenClientSecretHash = authTokenClientSecret.hashCode();

            TokenStoreEntry tokenStoreEntry = this.tokenStore.get(session.getContext().getRealm().getId());
            if (isValidAuthToken(authTokenUrl, authTokenScope, authTokenClientId, authTokenClientSecretHash, tokenStoreEntry)) {
                return tokenStoreEntry.token;
            }

            synchronized (this.tokenStore) {
                if (isValidAuthToken(authTokenUrl, authTokenScope, authTokenClientId, authTokenClientSecretHash, tokenStoreEntry)) {
                    return tokenStoreEntry.token;
                }

                JsonNode response = fetchTokenViaHTTP(session, authTokenUrl, authTokenScope, authTokenClientId, authTokenClientSecret);

                var maybeToken = getAccessToken(response);
                var maybeExpiresAt = getExpiresIn(response);

                if (maybeToken.isPresent()) {
                    var token = maybeToken.get();
                    this.tokenStore.put(session.getContext().getRealm().getId(),
                            new TokenStoreEntry(
                                    maybeExpiresAt.orElse(LocalDateTime.now()),
                                    authTokenUrl,
                                    authTokenScope,
                                    authTokenClientId,
                                    authTokenClientSecretHash,
                                    token));
                    return token;
                } else {
                    throw new EmailException("No access token found in token-response:" + response.asText());
                }
            }
        } catch (IOException e) {
            throw new EmailException("", e);
        }
    }

    private static boolean isValidAuthToken(String authTokenUrl, String authTokenScope, String authTokenClientId, int authTokenHash, TokenStoreEntry tokenStoreEntry) {
        return tokenStoreEntry != null
                && authTokenUrl != null && authTokenUrl.equals(tokenStoreEntry.url)
                && authTokenScope != null && authTokenScope.equals(tokenStoreEntry.scope)
                && authTokenClientId != null && authTokenClientId.equals(tokenStoreEntry.clientId)
                && authTokenHash == tokenStoreEntry.clientSecretHash
                && tokenStoreEntry.expiration_at.plusSeconds(30).isAfter(LocalDateTime.now());
    }

    private Optional<String> getAccessToken(JsonNode response) {
        if (response.has("access_token")) {
            return Optional.of(response.get("access_token").asText());
        } else {
            logger.warnf("No access_token found in response %s", response.asText());
            return Optional.empty();
        }
    }

    private Optional<LocalDateTime> getExpiresIn(JsonNode response) {
        //token-lifetime, must be given beside the token because token can be opaque (must not be a jwt token)
        if (response.has("expires_in")) {
            String expiresIn = response.get("expires_in").asText();
            return Optional.of(LocalDateTime.now().plusSeconds(Long.parseLong(expiresIn)));
        } else {
            logger.warnf("No expires_in found in response %s", response.asText());
            return Optional.empty();
        }
    }

    private JsonNode fetchTokenViaHTTP(KeycloakSession session, String authTokenUrl, String authTokenScope, String authTokenClientId, String authTokenClientSecret) throws IOException {
        JsonNode response = SimpleHttp.doPost(authTokenUrl, session)
                .param("client_id", authTokenClientId)
                .param("client_secret", authTokenClientSecret)
                .param("scope", authTokenScope)
                .param("grant_type", "client_credentials").asJson();
        return response;
    }

    record TokenStoreEntry(
            LocalDateTime expiration_at,
            String url,
            String token,
            String clientId,
            int clientSecretHash,
            String scope) {
    }
}
