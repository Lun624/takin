package xyz.masaimara.takin.config.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;

import java.util.Collection;

public class TakinUserApprovalHandler extends ApprovalStoreUserApprovalHandler {
    private boolean userApprovalStore = true;

    private ClientDetailsService clientDetailsService;

    public boolean isUserApprovalStore() {
        return userApprovalStore;
    }

    /**
     * @param userApprovalStore the useTokenServices to set
     */
    public void setUserApprovalStore(boolean userApprovalStore) {
        this.userApprovalStore = userApprovalStore;
    }

    public ClientDetailsService getClientDetailsService() {
        return clientDetailsService;
    }

    /**
     * Service to load client details (optional) for auto approval checks.
     *
     * @param clientDetailsService a client details service
     */
    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * Allows automatic approval for a white list of clients in the implicit grant case.
     *
     * @param authorizationRequest The authorization request.
     * @param userAuthentication   the current user authentication
     * @return An updated request if it has already been approved by the current user.
     */
    @Override
    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        boolean approved = false;
        if (userApprovalStore) {
            authorizationRequest = super.checkForPreApproval(authorizationRequest, userAuthentication);
            approved = authorizationRequest.isApproved();
        } else {
            if (null != clientDetailsService) {
                Collection<String> requestedScopes = authorizationRequest.getScope();
                try {
                    ClientDetails client = clientDetailsService
                            .loadClientByClientId(authorizationRequest.getClientId());
                    for (String scope : requestedScopes) {
                        if (client.isAutoApprove(scope)) {
                            approved = true;
                            break;
                        }
                    }
                } catch (ClientRegistrationException e) {

                }
            }
        }

        authorizationRequest.setApproved(approved);
        return authorizationRequest;
    }

}
