/*
 * jon.knight@forgerock.com
 *
 * Sets user profile attributes 
 *
 */

/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.handlers.RSASigningHandler;
import org.forgerock.json.schema.validator.Constants;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.json.jose.common.*;

import javax.inject.Inject;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.Callback;

import static org.forgerock.openam.auth.node.api.Action.send;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

//import org.forgerock.guava.common.base.Strings;
import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * A node which validates the incoming JWT
 *
 * <p>
 * Places the authorization code in shared state
 * </p>
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = ClientAssertionValidatorNode.Config.class)
public class ClientAssertionValidatorNode extends AbstractDecisionNode {

	public interface Config {
		@Attribute(order = 100)
		default String variable() {
			return "variable";
		}

		@Attribute(order = 200)
		default String prompt() {
			return "Prompt";
		}
	}

	private static final String BUNDLE = "org/forgerock/openam/auth/nodes/ClientAssertionValidatorNode";
	private final Logger logger = LoggerFactory.getLogger("amAuth");

	private final ClientAssertionValidatorNode.Config config;

	/**
	 * Constructs a new SetSessionPropertiesNode instance.
	 * 
	 * @param config Node configuration.
	 */
	@Inject
	public ClientAssertionValidatorNode(@Assisted ClientAssertionValidatorNode.Config config) {
		this.config = config;
	}

	private SignedJwt getSignedJwt(String sJWT) throws Exception{ 
    	logger.info("start of getsignedJwt");
    	SignedJwt signedJWT = null;
    	try { 
    		JwtReconstruction jwtReconstruction = new JwtReconstruction(); 
    		signedJWT = jwtReconstruction.reconstructJwt(sJWT, SignedJwt.class); 
    		logger.info("end of getsignedJwt ::::" + signedJWT); 
    	} catch (Exception ex) { 
    		logger.info("Exception in getsigned wt: "+ ex);
    		throw new Exception("Could not reconstruct JWT");
    	}
    	logger.info("end of getSignedJWT:::: " + signedJWT);
    	return signedJWT;
    }
    
    private boolean verifyJWSs(Key publicKey, String signedJWTs, JwsAlgorithm alg) {
    	logger.info("Start of Verify JWSs");
    	String signedData = signedJWTs.substring(0, signedJWTs.lastIndexOf("."));
    	String signatureB64u = signedJWTs.substring(signedJWTs.lastIndexOf(".") + 1, signedJWTs.length());
    	byte[] signature = Base64.getUrlDecoder().decode(signatureB64u);
    	RSASigningHandler rsaSigningHandler = new RSASigningHandler(publicKey);
    	logger.info("end of verify JWSs");
    	return rsaSigningHandler.verify(alg, signedData.getBytes(), signature);
    }
    
    public PublicKey stringToRSAKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String publicKeyB64 = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAufecY+YT179E9ZJ5NcDN"
        		+ "lvYZHZrDT+Xq/5fM5IGEJSME1DrJJ67j8PR7hUQ9ab7TiiVNzWhPDgPbmP0fD/Ao"
        		+ "haRTdlfayg+lCeXDu0oYTLwBtqrn+aBN+Oi57UsjLUi05j+j62fJfP6D9+dbZSHi"
        		+ "iNvc/0ETnG98IA2r8QFEM5qN3pprwOiVWa5nOb9BKvUix9HosDD3nGXpX18+/rtS"
        		+ "DmIOUF7O0Rgm/XCLr6zeB4IIdnMyLJMfaW4HyarEdaAeXIn1NfWOMGSZMquv4xsa"
        		+ "727F7Vd8eyf6WxD67hiPLh/G3nWPPbDAEGxynim6CYHFWtcg7o9AzuF8PCsas4OK"
        		+ "+dE3lAQymvXqm+PS9wD0A3/KD/UZONLfjWUg6Rb2dVBbirl/2hI2QnSv9yAbXlmg"
        		+ "z1fupElQNYAppjtK8ahU9Jvcupt7HIY1XYjc/XQhFU3cmZu7wAkZQd/8QFJntUT4"
        		+ "M9MuhNx/rq0cdACDyg8hl6nR5Ghoq0ExqfE6PrTl1ty7oegLjBzMYI4zQyv4nVRW"
        		+ "FqZUyCwLzeYFf8tkFhigOTogzklPPtKcyFxUYv/ScORl7n5yH/EkZsk1rK1xltu3"
        		+ "mwEmIQU3uelH8MUvhBFbrv9ejhDNrWkkSolIOkZShAvMPwW8ILvBy1DL9WghtMKE"
        		+ "noDBF0EDvzvoZMiD0r4KNLMCAwEAAQ==";
        
        
        
        
            byte[] byteKey = Base64.getDecoder().decode(publicKeyB64.getBytes());
	
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(X509publicKey);
        
    }
    
    public boolean verifyJWTExpiry(SignedJwt signedJWTs) throws GeneralSecurityException{
    	logger.info("Start of verifyJWTExpiry");
    	Date jwtExp =   (Date) (signedJWTs.getClaimsSet().getClaim("exp")); 
    	
        long secsFromEpoch = LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant().getEpochSecond();
        LocalDateTime ldt = LocalDateTime.ofInstant(jwtExp.toInstant(),
                ZoneId.systemDefault());
        long jwtExpsecs = ldt.atZone(ZoneId.systemDefault()).toInstant().getEpochSecond();
        
        logger.info("End of verifyJWTExpiry");
    	return jwtExpsecs>secsFromEpoch;
    }

    @SuppressWarnings("deprecation")
	@Override
	public Action process(TreeContext context) 
	{
		String token = context.request.headers.get("authorization").get(0).substring(7);
		String authorization_code = context.request.headers.get("code").get(0);

		logger.info("Authorization Code: "+authorization_code);

		JsonValue sharedState = context.sharedState;
		sharedState.put("authorizationCode", authorization_code);

		// Create Public key
			PublicKey publicKey;
			try{
				publicKey = this.stringToRSAKey();
				logger.info("Public Key: "+publicKey);
				
				
				//JWT Signature Validation
				
		    		Boolean validJWTSignature = this.verifyJWSs(publicKey, token, JwsAlgorithm.RS256);
		    		if (validJWTSignature)
		    		logger.info("JWT Signature is valid");
		    		else {
						logger.info("JWT Signature is invalid");
		    			return goTo(false).build();    			
		    		}
		    		
				 
				
				//verify expiry
				SignedJwt signedJwt = null;
				
					signedJwt = getSignedJwt(token);
					Boolean validExp = verifyJWTExpiry(signedJwt);
		    		if (validExp)
		    		logger.info("JWT is not expired");
		    		else {
						logger.info("JWT Signature is expired");
						return goTo(false).build();    			
		    		}
			}
			catch(InvalidKeySpecException | NoSuchAlgorithmException e){
				logger.error("Failed to read Public Key", e.getMessage());
				return goTo(false).build(); 
			}
			catch(GeneralSecurityException e){
				logger.error("JWT is expired", e.getMessage());
			}
			catch (Exception e) { 
				logger.error("JWT Signature is invalid",e.getMessage());
				return goTo(false).build();    			
		    }
		return goTo(true).replaceSharedState(sharedState).build();

	}
}