
package org.forgerock.openam.auth.nodes;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Base64;

import javax.inject.Inject;


import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.Exception.ClientNotFoundException;
import org.forgerock.openam.auth.Utility.HttpConnection;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;

import com.google.inject.assistedinject.Assisted;

/**
 * A node which validates the Client
 *
 * <p>
 * Places the Client ID in shared state
 * </p>
 */

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = ClientValidationNode.Config.class)
public class ClientValidationNode extends AbstractDecisionNode {

	public interface Config {
		@Attribute(order = 100)
		default String variable() {
			return "variable";
		}

		@Attribute(order = 200)
		default String prompt() {
			return "Prompt";
		}
		@Attribute(order=300)
		default String urlValue()
		{
			return "http://localhost:8080/openidm/endpoint/softwareStatement?clientName=";
		}
	}

	private static final String BUNDLE = "org/forgerock/openam/auth/nodes/ClientValidationNode";
	private final Logger logger = LoggerFactory.getLogger("amAuth");

	private final ClientValidationNode.Config config;

	/**
	 * Constructs a new SetSessionPropertiesNode instance.
	 * 
	 * @param config Node configuration.
	 */
	@Inject
	public ClientValidationNode(@Assisted ClientValidationNode.Config config) {
		this.config = config;
	}

    private HttpClient httpClient;

    public void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }
	
	@SuppressWarnings("deprecation")
	@Override
	public Action process(TreeContext context) 
	{
		logger.info("Client Validation Node");
        
		String jwtToken = context.request.headers.get("authorization").get(0).substring(7);
		String[] parts = jwtToken.split("\\.");
		JSONObject payload;
		JsonValue sharedState = context.sharedState;
		try 
		{
			payload = new JSONObject(new String(Base64.getUrlDecoder().decode(parts[1])));
			String sub=payload.getString("sub");
			sharedState.put("client-id", sub);
			httpClient = HttpClient.newBuilder().build();
			logger.info("Client Id:"+sub);
			
			HttpRequest request = HttpConnection.getRequest(this.config.urlValue()+sub);
			
			HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
			
			if(response.statusCode()==404)
			{
				logger.debug("Client Not Found: {}",response);
				throw new ClientNotFoundException("Client with Id: "+sub+" not found");
			}
			
		} 
		catch (JSONException | IOException | InterruptedException e) 
		{
			logger.error("Failed to validate client.", e.getMessage());
			return goTo(false).build();
		}

		catch(ClientNotFoundException e){
			logger.error("Client Not Found", e.getMessage());
			return goTo(false).build();
		}
		
		logger.info("Client is Valid");
		return goTo(true).replaceSharedState(sharedState).build();

	}
}