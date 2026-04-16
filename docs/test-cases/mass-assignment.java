// Test case: mass-assignment (API8:2023)
// Spring Boot example of mass assignment via BeanUtils
package com.example.demo.controller;

import org.springframework.beans.BeanUtils;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @PostMapping
    public User createUser(@RequestBody UserDto dto) {
        User entity = new User();
        // BUG: copies ALL matching fields including role, isAdmin
        BeanUtils.copyProperties(dto, entity);
        return userRepository.save(entity);
    }

    @PutMapping("/{id}")
    public User updateUser(@PathVariable Long id, @RequestBody UserDto dto) {
        User entity = userRepository.findById(id).orElseThrow();
        // BUG: no field filter -- attacker adds "role":"ADMIN" to JSON body
        BeanUtils.copyProperties(dto, entity);
        return userRepository.save(entity);
    }

    // UserDto accepts any field the client sends, including privileged ones
    public static class UserDto {
        private String username;
        private String email;
        private String role;      // BUG: should not be settable from input
        private Boolean isAdmin;  // BUG: should not be settable from input
    }
}
