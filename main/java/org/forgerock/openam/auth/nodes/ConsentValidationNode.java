package org.forgerock.openam.auth.nodes;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.Exception.ConsentIdNotFoundException;
import org.forgerock.openam.auth.Utility.HttpConnection;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;

/**
 * A node which validates the Consent
 *
 * <p>
 * Places the consent ID in shared state
 * </p>
 */

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
                configClass = ConsentValidationNode.Config.class)
public class ConsentValidationNode extends AbstractDecisionNode {
	public interface Config {
        @Attribute(order = 100)
        default String variable() { return "variable"; }

        @Attribute(order = 200)
        default String prompt() { return "Prompt"; }
        
        @Attribute(order=300)
        default String urlValue()
        {
        	return "http://localhost:8080/openidm/endpoint/consent?clientId=";
        }
        
    }
	
	private static final String BUNDLE = "org/forgerock/openam/auth/nodes/ConsentValidationNode";
	private final ConsentValidationNode.Config config;
    private final Logger logger = LoggerFactory.getLogger("amAuth");
	
	@Inject
    public ConsentValidationNode(@Assisted ConsentValidationNode.Config config) {
        this.config = config;
    }

    private static LocalDateTime getDateTimeFromString(String dateString) {
        // Sample DateTime Mon Jul 03 2023 18:14:09 GMT+0530 (IST)

        // Define the format pattern to match the input string
        // DateTimeFormatter formatter = DateTimeFormatter.ISO_INSTANT;

        // Parse the string into a ZonedDateTime
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(dateString);

        // Set the time zone to India
        ZoneId indiaZone = ZoneId.of("Asia/Kolkata");
        ZonedDateTime indiaDateTime = zonedDateTime.withZoneSameInstant(indiaZone);

        // Convert the ZonedDateTime to LocalDateTime
        LocalDateTime localDateTime = indiaDateTime.toLocalDateTime();
        return localDateTime;
    }
    
    @SuppressWarnings("deprecation")
	@Override
	public Action process(TreeContext context) {
		
        logger.info("Consent Validation Node");

        String clientId = context.sharedState.get("client-id").asString();
        logger.info("Client Id: "+clientId);
        JsonValue sharedState = context.sharedState;

        HttpRequest request = HttpConnection.getRequest(this.config.urlValue() + clientId);

        HttpResponse<String> response = null;

        try {
            response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            JSONObject obj = new JSONObject(response.body());
            JSONArray arr = obj.getJSONArray("ClientDetails");

            String consentId = arr.getJSONObject(0).getString("_id");
            if(consentId==null || consentId.isEmpty()){
                logger.debug("No Consent Id found for the client: {}",consentId);
                throw new ConsentIdNotFoundException("Consent Id: "+consentId+" not found");
            }
            //Storing Consent Id in Consent State
            sharedState.put("consentId", consentId);

            //Expiry Validation of Consent
            String consentExpiryDateTime = arr.getJSONObject(0).getString("consentExpiryDateTime");
            
            if (LocalDateTime.now().compareTo(getDateTimeFromString(consentExpiryDateTime))>=0) {
                System.out.println("Expired Consent");
                logger.info("Expired Consent");
                return goTo(false).build();
            }

        } 
        catch(ConsentIdNotFoundException e){
            logger.error("Consent Not Found", e.getMessage());
            return goTo(false).build();
        }
        catch (Exception e) {
            logger.error("Failed to validate consent", e.getMessage());
            return goTo(false).build();
        }
        logger.info("Success"); 
        return goTo(true).replaceSharedState(sharedState).build();
    }

    
}
