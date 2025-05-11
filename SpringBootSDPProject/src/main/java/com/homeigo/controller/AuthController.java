package com.homeigo.controller;

import com.homeigo.model.User;
import com.homeigo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class AuthController {
    @Autowired
    private UserService userService;

    @PostMapping("/admin/login")
    public ResponseEntity<?> adminLogin(@RequestBody LoginRequest loginRequest) {
        try {
            User user = userService.authenticate(loginRequest.getUsername(), loginRequest.getPassword());
            if (user.getRole() != UserRole.ADMIN) {
                throw new RuntimeException("Invalid credentials for admin access");
            }
            Map<String, Object> response = new HashMap<>();
            response.put("user", user);
            response.put("message", "Admin login successful");
            response.put("redirect", "/admin");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/provider/login")
    public ResponseEntity<?> providerLogin(@RequestBody LoginRequest loginRequest) {
        try {
            User user = userService.authenticate(loginRequest.getUsername(), loginRequest.getPassword());
            if (user.getRole() != UserRole.PROVIDER) {
                throw new RuntimeException("Invalid credentials for provider access");
            }
            Map<String, Object> response = new HashMap<>();
            response.put("user", user);
            response.put("message", "Provider login successful");
            response.put("redirect", "/provider");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/customer/login")
    public ResponseEntity<?> customerLogin(@RequestBody LoginRequest loginRequest) {
        try {
            User user = userService.authenticate(loginRequest.getUsername(), loginRequest.getPassword());
            if (user.getRole() != UserRole.CUSTOMER) {
                throw new RuntimeException("Invalid credentials for customer access");
            }
            Map<String, Object> response = new HashMap<>();
            response.put("user", user);
            response.put("message", "Customer login successful");
            response.put("redirect", "/customer");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        try {
            User registeredUser = userService.registerUser(user);
            Map<String, Object> response = new HashMap<>();
            response.put("user", registeredUser);
            response.put("message", "Registration successful");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @GetMapping("/check-role/{username}")
    public ResponseEntity<?> checkRole(@PathVariable String username) {
        try {
            User user = userService.findByUsername(username);
            Map<String, Object> response = new HashMap<>();
            response.put("role", user.getRole());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
}

class LoginRequest {
    private String username;
    private String password;

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
} 