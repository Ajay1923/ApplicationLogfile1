package com.crud.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.crud.demo.model.User;
import com.crud.demo.repository.UserRepository;

import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public User saveUser(User user) {
        return userRepository.save(user);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }
    
    //public Optional<User> loginWithUsernameOrEmail(String identifier, String password) {
       // return userRepository.findByUsernameOrEmailAndPassword(identifier, identifier, password);
   // }
    public Optional<User> loginWithUsernameOrEmail(String identifier, String password) {
        return userRepository.findByUsernameOrEmailIgnoreCaseAndPassword(identifier, password);
    }


    public List<User> findUsersByCriteria(String searchTerm) {
        return userRepository.findByFirstNameContainingOrLastNameContainingOrEmailContainingOrMobileNumberContainingOrUsernameContaining(
            searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
    }

    public List<User> findUsersByAccess(String access) {
        return userRepository.findByAccess(access);
    }

    public List<User> findUsersByCriteriaAndAccess(String searchTerm, String access) {
        return userRepository.findByFirstNameContainingOrLastNameContainingOrEmailContainingOrMobileNumberContainingOrUsernameContainingAndAccess(
            searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, access);
    }

    public User updateUser(Long id, User userDetails) {
        Optional<User> userOptional = userRepository.findById(id);
        if (userOptional.isPresent()) {
            User existingUser = userOptional.get();
            existingUser.setUsername(userDetails.getUsername());

            // Update password only if it is provided
            if (userDetails.getPassword() != null && !userDetails.getPassword().isEmpty()) {
                existingUser.setPassword(userDetails.getPassword());
            }
            existingUser.setFirstName(userDetails.getFirstName());
            existingUser.setMiddleName(userDetails.getMiddleName());
            existingUser.setLastName(userDetails.getLastName());
            existingUser.setDateOfBirth(userDetails.getDateOfBirth());
            existingUser.setGender(userDetails.getGender());
            existingUser.setEmail(userDetails.getEmail());
            existingUser.setMobileNumber(userDetails.getMobileNumber());
            existingUser.setAccess(userDetails.getAccess());  // Update the access level
            return userRepository.save(existingUser);
        }
        return null; // Handle this case appropriately in your application
    }

    public void addUser(User user) {
        userRepository.save(user);
    }

    public void updateUser(User user) {
        userRepository.save(user);
    }
    @Transactional
    public String registerUser(User user) {
        // Check if the username already exists
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return "Username already exists!";
        }

        // Save the new user
        userRepository.save(user);
        return "Registration successful";
    }

	
    
  
   
}
