package com.deliveryapp.backend.auth;

import com.deliveryapp.backend.auth.dto.RegisterRequest;
import com.deliveryapp.backend.user.Role;
import com.deliveryapp.backend.user.User;
import com.deliveryapp.backend.user.UserRepository;
import jakarta.validation.Valid;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepository,
                          BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public String register(@Valid @RequestBody RegisterRequest request) {

        String email = request.getEmail().toLowerCase();

        if (userRepository.existsByEmail(email)) {
            return "Email already registered";
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);
        user.setVerified(false);
        user.setActive(true);

        userRepository.save(user);

        return "User registered successfully. Please verify your email.";
    }
}
