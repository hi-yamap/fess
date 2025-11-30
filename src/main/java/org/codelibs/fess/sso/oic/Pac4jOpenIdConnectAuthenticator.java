package org.codelibs.fess.sso.oic;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.codelibs.core.lang.StringUtil;
import org.codelibs.fess.app.web.base.login.ActionResponseCredential;
import org.codelibs.fess.app.web.base.login.FessLoginAssist.LoginCredentialResolver;
import org.codelibs.fess.app.web.base.login.OpenIdConnectCredential;
import org.codelibs.fess.mylasta.action.FessUserBean;
import org.codelibs.fess.sso.SsoAuthenticator;
import org.codelibs.fess.sso.SsoResponseType;
import org.codelibs.fess.util.ComponentUtil;
import org.lastaflute.web.login.credential.LoginCredential;
import org.lastaflute.web.response.ActionResponse;
import org.lastaflute.web.response.HtmlResponse;
import org.lastaflute.web.util.LaRequestUtil;
import org.lastaflute.web.util.LaResponseUtil;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.session.JEESessionStore;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.jakartaee.context.JEEContext;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.OidcProfile;

/**
 * OpenID Connect authenticator based on pac4j framework.
 * Provides automatic token refresh and robust session management.
 */
public class Pac4jOpenIdConnectAuthenticator implements SsoAuthenticator {

    private static final Logger logger = LogManager.getLogger(Pac4jOpenIdConnectAuthenticator.class);

    @PostConstruct
    public void init() {
        if (logger.isDebugEnabled()) {
            logger.debug("Initialize {}", this.getClass().getSimpleName());
        }
        ComponentUtil.getSsoManager().register(this);
    }

    // =====================
    // Settings from system
    // =====================
    protected String getClientId() {
        return ComponentUtil.getSystemProperties().getProperty("oic.client.id");
    }

    protected String getClientSecret() {
        return ComponentUtil.getSystemProperties().getProperty("oic.client.secret");
    }

    protected String getScope() {
        return ComponentUtil.getSystemProperties().getProperty("oic.scope", "openid email profile");
    }

    protected String getRedirectUrl() {
        return ComponentUtil.getSystemProperties().getProperty("oic.redirect.url", "http://localhost:8080/sso/");
    }

    protected String getIssuer() {
        return ComponentUtil.getSystemProperties().getProperty("oic.issuer");
    }

    protected String getDiscoveryUri() {
        return ComponentUtil.getSystemProperties().getProperty("oic.discovery.uri");
    }

    // ============
    // Main flows
    // ============
    @Override
    public LoginCredential getLoginCredential() {
        return LaRequestUtil.getOptionalRequest().map(req -> process(req, LaResponseUtil.getResponse())).orElse(null);
    }

    protected LoginCredential process(final HttpServletRequest request, final HttpServletResponse response) {
        final JEEContext ctx = new JEEContext(request, response);
        final Config config = buildConfig();
        final ProfileManager manager = new ProfileManager(ctx, config.getSessionStore());

        // 1) Check existing profile and refresh if expired
        final Optional<UserProfile> existing = manager.getProfile();
        if (existing.isPresent()) {
            final UserProfile profile = existing.get();
            if (profile instanceof OidcProfile oidc) {
                if (isExpired(oidc)) {
                    // Try to refresh token if refresh_token is available
                    final OidcClient client = (OidcClient) config.getClients().findClient("oidc").orElseThrow();
                    try {
                        final var optRef = oidc.getRefreshToken();
                        if (StringUtil.isNotBlank(optRef)) {
                            client.renewToken(ctx, oidc);
                            // Profile is updated after renewal, save and return
                            manager.save(oidc, true);
                            return toCredential(oidc);
                        }
                    } catch (Exception e) {
                        // Refresh failed: fallback to redirect below
                    }
                } else {
                    return toCredential(oidc);
                }
            }
        }

        // 2) Handle callback or start authentication
        final OidcClient client = (OidcClient) config.getClients().findClient("oidc").orElseThrow();
        final String code = request.getParameter("code");
        final String state = request.getParameter("state");
        try {
            if (StringUtil.isNotBlank(code) && StringUtil.isNotBlank(state)) {
                final var credentials = client.getCredentials(ctx);
                final var profile = client.getUserProfile(credentials, ctx);
                manager.save(profile, true);
                return toCredential((OidcProfile) profile);
            } else {
                final var actionOpt = client.getRedirectionAction(ctx);
                if (actionOpt.isPresent() && actionOpt.get() instanceof RedirectionAction ra) {
                    final String location = ra.getLocation();
                    return new ActionResponseCredential(() -> HtmlResponse.fromRedirectPathAsIs(location));
                }
            }
        } catch (final Exception e) {
            final var actionOpt = client.getRedirectionAction(ctx);
            if (actionOpt.isPresent() && actionOpt.get() instanceof RedirectionAction ra) {
                final String location = ra.getLocation();
                return new ActionResponseCredential(() -> HtmlResponse.fromRedirectPathAsIs(location));
            }
        }
        return null;
    }

    protected boolean isExpired(final OidcProfile profile) {
        final Integer exp = profile.getExpirationDate() != null ? (int) (profile.getExpirationDate().getTime() / 1000) : null;
        if (exp == null) return false;
        final long nowSec = System.currentTimeMillis() / 1000L;
        // Refresh 60 seconds before expiration
        return nowSec + 60 >= exp;
    }

    protected Config buildConfig() {
        final OidcConfiguration conf = new OidcConfiguration();
        conf.setClientId(getClientId());
        conf.setSecret(getClientSecret());
        if (StringUtil.isNotBlank(getDiscoveryUri())) {
            conf.setDiscoveryURI(getDiscoveryUri());
        } else if (StringUtil.isNotBlank(getIssuer())) {
            conf.setIssuer(getIssuer());
        }
        conf.setScope(getScope());
        conf.setUseNonce(true);
        conf.setWithState(true);
        conf.setPreferredJwsAlgorithm(null); // Delegate to provider

        final OidcClient client = new OidcClient(conf);
        client.setName("oidc");
        client.setCallbackUrl(getRedirectUrl());

        final Clients clients = new Clients(getRedirectUrl(), client);
        final Config config = new Config(clients);
        config.setSessionStore(JEESessionStore.INSTANCE);
        return config;
    }

    protected LoginCredential toCredential(final OidcProfile profile) {
        final Map<String, Object> attrs = new HashMap<>(profile.getAttributes());
        final String email = (String) Optional.ofNullable(attrs.get("email"))
                .orElse(profile.getAttribute("preferred_username", String.class));
        attrs.put("email", email);
        // Store pac4j profile fields in standardized format
        attrs.putIfAbsent("id_token", profile.getIdToken());
        attrs.putIfAbsent("access_token", profile.getAccessToken());
        attrs.putIfAbsent("refresh_token", profile.getRefreshToken());
        if (profile.getExpirationDate() != null) {
            attrs.put("expire", profile.getExpirationDate().getTime() / 1000);
        }
        return new OpenIdConnectCredential(attrs);
    }

    @Override
    public void resolveCredential(final LoginCredentialResolver resolver) {
        resolver.resolve(OpenIdConnectCredential.class, credential -> org.dbflute.optional.OptionalEntity.of(credential.getUser()));
    }

    @Override
    public ActionResponse getResponse(final SsoResponseType responseType) {
        return null;
    }

    @Override
    public String logout(final FessUserBean user) {
        return null;
    }
}

