package org.forgerock.openam.auth.Utility;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

public class ConsentTestUtility {

    private static final String url = "http://localhost:8080/openidm/managed/Consent/";
    private static HttpRequest request;
    private static HttpResponse<String> response;
    private static HttpClient client;

    public static JSONObject createTestConsent(String personId,String personLastName, String personEmail, String consentReAuthorisationDateTime,String consentStartDateTime, String scope, String orgId,String clientIdanzSSAId,String clientId,String status, String consentId, LocalDateTime now, LocalDateTime expiry)
            throws IOException, InterruptedException, JSONException {
        //creating dummy consent for test

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        String sb = "{" +
                "\"personId\": \"" + personId + "\"," +
                "\"personLastName\": \"" + personLastName + "\"," +
                "\"personEmail\": \"" + personEmail + "\"," +
                "\"consentReAuthorisationDateTime\": \"" + consentReAuthorisationDateTime + "\"," +
                "\"consentStartDateTime\": \"" + consentStartDateTime + "\"," +
                "\"scope\": \"" + scope + "\"," +
                "\"orgId\": \"" + orgId + "\"," +
                "\"clientIdanzSSAId\": \"" + clientIdanzSSAId + "\"," +
                "\"clientId\": \"" + clientId + "\"," +
                "\"status\": \"" + status + "\"," +
                "\"statusUpdateDateTime\": \"" + now.toString() + "\"," +
                "\"consentId\": \"" + consentId + "\"," +
                "\"consentExpiryDateTime\": \"" + expiry.toString() + "\"}";

        request = HttpConnection.sendRequest(url, "POST", headers, sb);
        client = HttpClient.newBuilder().build();
        response = client.send(request, HttpResponse.BodyHandlers.ofString());

        return new JSONObject(response.body());
    }

    public static void deleteConsent(String _id) throws IOException, InterruptedException {
        request = HttpConnection.sendRequest(url + _id, "DELETE", null, null);
        response = client.send(request, HttpResponse.BodyHandlers.ofString());
    }

}