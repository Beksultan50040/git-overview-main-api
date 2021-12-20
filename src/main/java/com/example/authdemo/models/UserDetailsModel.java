package com.example.authdemo.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashMap;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsModel {

    private String email;
    private String id;
    private ArrayList<String> roles;
    private String userId;
    private HashMap<String, ArrayList<String>> acl;

    public void setEmail(String email) {
        this.email = email;
        getUserIDByEmail();
    }

    private void getUserIDByEmail() {
        userId = email.replaceAll("@dar.kz", "").replaceAll("@index.com", "");
    }
}
