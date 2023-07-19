package org.forgerock.openam.auth.Exception;

public class AccessTokenGenerationException extends RuntimeException{
    public AccessTokenGenerationException(String message){
        super(message);
    }
}
