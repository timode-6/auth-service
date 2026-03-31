package com.example.auth_service.exception;

public class UserAlreadyExistsException extends RuntimeException{

    public UserAlreadyExistsException(String login){
        super("User with login '" + login + "' already exists");
    }
}