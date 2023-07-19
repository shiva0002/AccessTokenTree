package org.forgerock.openam.auth.Exception;

public class ClientNotFoundException extends RuntimeException {
    
    public ClientNotFoundException(String message){
        super(message);
    }
}
