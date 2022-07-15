package com.example.authenticationapi.controller;

import com.example.authenticationapi.model.ERole;
import com.example.authenticationapi.model.Role;
import com.example.authenticationapi.model.User;
import com.example.authenticationapi.payload.SignupRequest;
import com.example.authenticationapi.payload.response.MessageResponse;
import com.example.authenticationapi.payload.response.UserResource;
import com.example.authenticationapi.repository.RoleRepository;
import com.example.authenticationapi.repository.UserRepository;
import com.example.authenticationapi.service.UserDetailsServiceImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api")
public class UserController {

    private final PasswordEncoder encoder;
    private final UserDetailsServiceImpl userDetailsService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public UserController(UserDetailsServiceImpl userDetailsService, UserRepository userRepository, PasswordEncoder encoder, RoleRepository roleRepository) {
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.roleRepository = roleRepository;
    }

    @GetMapping("/user/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResource>> allAccess() {
        final List<User> mentors = userRepository.findByRoleName(ERole.ROLE_MENTOR.name());
        final List<User> students = userRepository.findByRoleName(ERole.ROLE_STUDENT.name());
        final List<User> allUser = new ArrayList<>();
        allUser.addAll(mentors);
        allUser.addAll(students);
        return getListResponseEntity(allUser);
    }

    @GetMapping("/user/student")
    @PreAuthorize("hasRole('STUDENT')")
    public ResponseEntity<List<UserResource>> userAccess() {
        final List<User> mentors = userRepository.findByRoleName(ERole.ROLE_MENTOR.name());
        return getListResponseEntity(mentors);
    }

    @GetMapping("/user/mentor")
    @PreAuthorize("hasRole('MENTOR')")
    public ResponseEntity<List<UserResource>> moderatorAccess() {
        final List<User> mentors = userRepository.findByRoleName(ERole.ROLE_STUDENT.name());
        return getListResponseEntity(mentors);
    }

    @PostMapping("/user")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }
        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        if (strRoles.isEmpty()) {
            Role userRole = roleRepository.findByName(ERole.ROLE_STUDENT)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mentor":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MENTOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_STUDENT)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @DeleteMapping("/user/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUserById(@Valid @PathVariable("id") Long id) {
        userRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    private ResponseEntity<List<UserResource>> getListResponseEntity(List<User> users) {
        final List<UserResource> userResources = new ArrayList<>();
        users.forEach(u -> {
            UserDetails userDetail = userDetailsService.loadUserByUsername(u.getUsername());
            final UserResource resource = new UserResource();
            resource.setId(u.getId());
            resource.setEmail(u.getEmail());
            resource.setAuthorities(userDetail.getAuthorities());
            resource.setUsername(userDetail.getUsername());
            resource.setEnabled(userDetail.isEnabled());
            userResources.add(resource);
        });

        return ResponseEntity.ok(userResources);
    }

}