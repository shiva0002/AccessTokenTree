package org.forgerock.openam.auth.nodes;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.Exception.AccessTokenGenerationException;
import org.forgerock.openam.auth.Utility.HttpConnection;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;

/**
 * A node which generates the access token from the authorization code
 *
 * <p>
 * Places the access token in session property
 * </p>
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
                configClass = GenerateAccessTokenNode.Config.class)
public class GenerateAccessTokenNode extends AbstractDecisionNode {

    final Map<String,String> params = new HashMap<String,String>();
    
	public interface Config {
        @Attribute(order = 100)
        default String variable() { return "variable"; }

        @Attribute(order = 200)
        default String prompt() { return "Prompt"; }
        
        @Attribute(order=300)
        default String urlValue() {return "http://openam.example.com:9090/openam/oauth2/realms/root/realms/demo/access_token"; }
        @Attribute(order=400)
        default String clientId()
        {
        	return "ClientId";
        }
        @Attribute(order=500)
        default String clientSecret()
        {
        	return "ClientSecret";
        }
    }
	
	private static final String BUNDLE = "org/forgerock/openam/auth/nodes/GenerateAccessTokenNode";
	private final GenerateAccessTokenNode.Config config;
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    
	
	@Inject
    public GenerateAccessTokenNode(@Assisted GenerateAccessTokenNode.Config config) {
        this.config = config;
    }

    @SuppressWarnings("deprecation")
	@Override
	public Action process(TreeContext context) {
	    
        logger.info("Generate Access Token Node");
        
        String authCode = context.sharedState.get("authorizationCode").asString();
        
        logger.info("Auth Code is: "+ authCode);
		// Access the shared state
        JsonValue sharedState = context.sharedState;   

        String url = this.config.urlValue();
        String clientId = this.config.clientId();
        String clientSecret = this.config.clientSecret();
        String authorization = clientId + ":" + clientSecret;
        String encodedAuthorization = Base64.getEncoder().encodeToString(authorization.getBytes(StandardCharsets.UTF_8));
        String grantType = "authorization_code";
        String accessToken;
        try {

            String data = "grant_type=" + grantType + "&code=" + authCode;

            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            headers.put("Authorization", "Basic " + encodedAuthorization);

            HttpRequest request = HttpConnection.sendRequest(url + "?" + data, "POST", headers, null);
            HttpResponse<String> response = HttpClient.newBuilder().build().send(request, HttpResponse.BodyHandlers.ofString());

            JSONObject body = new JSONObject(response.body());
            accessToken = body.get("access_token").toString();

            logger.info("Response: " + response.body());

            if (accessToken == null) {
                throw new AccessTokenGenerationException("Access token generation failed");
            }
            // Store data in the shared state
            sharedState.put("accessToken", accessToken);
            
			logger.debug("Access Token: {}",accessToken);    
        } 
        catch(AccessTokenGenerationException e){
            logger.error("Access token generation failed", e.getMessage());
            return goTo(false).build();
        }
        catch (Exception e) {
            logger.error("Invalid Access Token",e.getMessage());
            return goTo(false).build();
        }
        
        return goTo(true).putSessionProperty("access_token", accessToken).replaceSharedState(sharedState).build();
        
	}
}
