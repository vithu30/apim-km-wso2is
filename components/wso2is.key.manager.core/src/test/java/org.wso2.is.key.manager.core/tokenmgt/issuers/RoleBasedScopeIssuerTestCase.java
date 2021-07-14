package org.wso2.is.key.manager.core.tokenmgt.issuers;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.junit4.PowerMockRunner;
import org.testng.Assert;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.DefaultRealm;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.cache.Cache;
import javax.cache.CacheManager;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

@RunWith(PowerMockRunner.class)
@PrepareForTest({IdentityTenantUtil.class})
@SuppressStaticInitializationFor("org.wso2.carbon.identity.oauth2.util.OAuth2Util")
public class RoleBasedScopeIssuerTestCase {

    private RealmService realmService = Mockito.mock(RealmService.class);
    private CacheManager cacheManager = Mockito.mock(CacheManager.class);
    private TenantManager tenantManager = Mockito.mock(TenantManager.class);
    private Cache cache = Mockito.mock(Cache.class);
    private DefaultRealm defaultRealm = Mockito.mock(DefaultRealm.class);
    private AbstractUserStoreManager abstractUserStoreManager = Mockito.mock(AbstractUserStoreManager.class);

    @Test
    public void testGetScopesForRolesWithOpenIDScope() throws Exception {

        final String tenantDomain = "carbon.super";
        final String clientId = "clientId";
        final String scope = "scope";
        Mockito.when(cacheManager.getCache(anyString())).thenReturn(cache);
        Mockito.when(realmService.getTenantManager()).thenReturn(tenantManager);
        Mockito.when(tenantManager.getTenantId(anyString())).thenReturn(-1234);
        Mockito.when(realmService.getTenantUserRealm(Mockito.anyInt()))
                .thenReturn(defaultRealm);
        Mockito.when(abstractUserStoreManager.getRoleListOfUser(anyString())).thenReturn
                (new String[]{"api_view"});
        Mockito.when(defaultRealm.getUserStoreManager()).thenReturn(abstractUserStoreManager);
        Map<String, String> restAPIScopes = new HashMap<String, String>();
        restAPIScopes.put("api_view", "api_view");
        Mockito.when(cache.get(anyString())).thenReturn(restAPIScopes);

        OAuth2AccessTokenReqDTO tokenDTO = new OAuth2AccessTokenReqDTO();
        tokenDTO.setClientId(clientId);
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(tokenDTO);
        tokReqMsgCtx.setScope(new String[]{scope, "openid"});
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName("admin");
        authenticatedUser.setUserStoreDomain("admin.user.store.domain");
        authenticatedUser.setFederatedUser(true);

        Map<ClaimMapping, String> userAttributes = new HashMap<ClaimMapping, String>();
        userAttributes.put(buildClaimMapping(), "localRole");

        authenticatedUser.setUserAttributes(userAttributes);
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        OAuthCallback oAuthCallback = new OAuthCallback(authenticatedUser, "admin", OAuthCallback.
                OAuthCallbackType.SCOPE_VALIDATION_AUTHZ);
        oAuthCallback.setRequestedScope(new String[]{"openid", scope});

        RoleBasedScopesIssuer roleBasedScopesIssuer = new RoleBasedScopesIssuer();


        RoleBasedScopesIssuer spy = PowerMockito.spy(roleBasedScopesIssuer);
        PowerMockito.doReturn("role").when(spy, "getOIDCMappedLocalClaimURI", "carbon.super");

        Mockito.when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);

        List<String> scopes = roleBasedScopesIssuer.getScopes(oAuthCallback);
        Assert.assertEquals(2, scopes.size());
        Assert.assertTrue(scopes.contains(scope));
    }

    private ClaimMapping buildClaimMapping() {

        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri("role");
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        return claimMapping;
    }
}
