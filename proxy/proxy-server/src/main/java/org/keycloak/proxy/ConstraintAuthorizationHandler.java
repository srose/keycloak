package org.keycloak.proxy;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HttpString;
import org.keycloak.adapters.undertow.KeycloakUndertowAccount;
import org.keycloak.representations.UserClaimSet;
import org.keycloak.representations.IDToken;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ConstraintAuthorizationHandler implements HttpHandler {

    protected HttpHandler next;
    protected String errorPage;
    protected ProxyConfig.IdentityHeaderNames identityHeaderNames;

    protected final HttpString httpHeaderSubject;
    protected final HttpString httpHeaderUserName;
    protected final HttpString httpHeaderEmail;
    protected final HttpString httpHeaderName;
    protected final HttpString httpHeaderAccessToken;

    public ConstraintAuthorizationHandler(HttpHandler next, String errorPage, ProxyConfig.IdentityHeaderNames identityHeaderNames) {
        this.next = next;
        this.errorPage = errorPage;
        if(identityHeaderNames != null) {
            this.httpHeaderSubject = getHttpStringOrNull(identityHeaderNames.getSubject());
            this.httpHeaderUserName = getHttpStringOrNull(identityHeaderNames.getUserName());
            this.httpHeaderEmail = getHttpStringOrNull(identityHeaderNames.getEmail());
            this.httpHeaderName = getHttpStringOrNull(identityHeaderNames.getName());
            this.httpHeaderAccessToken = getHttpStringOrNull(identityHeaderNames.getAccessToken());
        } else {
            this.httpHeaderSubject = null;
            this.httpHeaderUserName = null;
            this.httpHeaderEmail = null;
            this.httpHeaderName = null;
            this.httpHeaderAccessToken = null;
        }
    }

    private HttpString getHttpStringOrNull(String string) {
        if(string == null) {
            return null;
        }
        return new HttpString(string);
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        KeycloakUndertowAccount account = (KeycloakUndertowAccount)exchange.getSecurityContext().getAuthenticatedAccount();
        SingleConstraintMatch match = exchange.getAttachment(ConstraintMatcherHandler.CONSTRAINT_KEY);
        if (match == null || (match.getRequiredRoles().isEmpty() && match.getEmptyRoleSemantic() == SecurityInfo.EmptyRoleSemantic.AUTHENTICATE)) {
            authenticatedRequest(account, exchange);
            return;
        }
        if (match != null) {
            for (String role : match.getRequiredRoles()) {
                if (account.getRoles().contains(role)) {
                    authenticatedRequest(account, exchange);
                    return;
                }
            }
        }
        if (errorPage != null) {
            exchange.setRequestPath(errorPage);
            exchange.setRelativePath(errorPage);
            exchange.setResolvedPath(errorPage);
            next.handleRequest(exchange);
            return;

        }
        exchange.setResponseCode(403);
        exchange.endExchange();

    }

    public void authenticatedRequest(KeycloakUndertowAccount account, HttpServerExchange exchange) throws Exception {
        if (account != null) {
            IDToken idToken = account.getKeycloakSecurityContext().getToken();
            if (idToken == null) return;
            if (idToken.getSubject() != null && httpHeaderSubject != null) {
                exchange.getRequestHeaders().put(httpHeaderSubject, idToken.getSubject());
            }

            UserClaimSet claimSet = idToken.getUserClaimSet();

            if (claimSet.getPreferredUsername() != null && httpHeaderUserName != null) {
                exchange.getRequestHeaders().put(httpHeaderUserName, claimSet.getPreferredUsername());
            }
            if (claimSet.getEmail() != null && httpHeaderEmail != null) {
                exchange.getRequestHeaders().put(httpHeaderEmail, claimSet.getEmail());
            }
            if (claimSet.getName() != null && httpHeaderName != null) {
                exchange.getRequestHeaders().put(httpHeaderName, claimSet.getName());
            }
            if (httpHeaderAccessToken != null) {
                exchange.getRequestHeaders().put(httpHeaderAccessToken, account.getKeycloakSecurityContext().getTokenString());
            }
        }
        next.handleRequest(exchange);
    }
}
