package com.example.authenticationapi.payload.response;

import com.example.authenticationapi.model.ERole;
import com.example.authenticationapi.model.Role;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
public class UserResource {
    private Long id;
    private String username;
    private String email;
    private Collection<? extends GrantedAuthority> authorities;
    private Boolean enabled;

}
