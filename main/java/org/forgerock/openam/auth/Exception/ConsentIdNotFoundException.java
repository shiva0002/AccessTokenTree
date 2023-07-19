package org.forgerock.openam.auth.Exception;

public class ConsentIdNotFoundException extends RuntimeException{
    public ConsentIdNotFoundException(String message){
        super(message);
    }
}
