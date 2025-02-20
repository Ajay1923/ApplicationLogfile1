package com.crud.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import com.crud.demo.model.User;
import com.crud.demo.repository.UserRepository;
import com.crud.demo.service.UserService;

import java.util.List;
import java.util.Optional;
import javax.servlet.http.HttpSession;
import javax.transaction.Transactional;


@Controller
public class UserController {


    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HttpSession httpSession;

    @Autowired
    private UserService userService;

    @GetMapping("/login")
    public String showLoginForm() {
        return "login";
    }
   
    @PostMapping("/login")
    public String handleLogin(@RequestParam String identifier, @RequestParam String password, Model model) {
        Optional<User> userOptional = userService.loginWithUsernameOrEmail(identifier, password);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            httpSession.setAttribute("userId", user.getId());
            httpSession.setAttribute("userRole", user.getAccess());
            System.out.println("User access level set to: " + user.getAccess());
            return "redirect:/webpage";
        } else {
            model.addAttribute("error", "Invalid username/email or password");
            return "login";
        }
    }


    @GetMapping("/logout")
    public String handleLogout() {
        httpSession.invalidate();
        return "redirect:/login";
    }

    @GetMapping("/settings")
    public String showSettingsPage(Model model) {
        Long userId = (Long) httpSession.getAttribute("userId");
        if (userId == null) {
            return "redirect:/login"; // Redirect to login if no user is logged in
        }

        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            model.addAttribute("user", userOptional.get());
        } else {
            model.addAttribute("error", "User not found.");
        }
        return "settings";
    }


    @GetMapping("/settings/edit")
    public String editUserDetails(@RequestParam(required = false) Long userId, Model model) {
        if (userId == null) {
            model.addAttribute("error", "Invalid user ID.");
            return "redirect:/settings";
        }

        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            model.addAttribute("user", userOptional.get());
            return "editUser"; // Separate page or modal for editing
        } else {
            model.addAttribute("error", "User not found.");
            return "redirect:/settings";
        }
    }


    @PostMapping("/Logging_cred")
    public String handleUserDetailsSubmission(@ModelAttribute User user, RedirectAttributes redirectAttributes) {
        user.setEnabled(true); // Enable user by default

        // Validate required fields
        if (user.getFirstName().isEmpty() || user.getEmail().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "All fields are required.");
                return "redirect:/settings"; 
            }

        // Check if the user has an ID for update, else create a new user
        if (user.getId() != null) {
            return updateUser(user, redirectAttributes);
        } else {
            return createUser(user, redirectAttributes); // Handle new user creation
        }
    }

    private boolean isUserDetailsInvalid(User user) {
        return user.getFirstName() == null || user.getFirstName().isEmpty() ||                       
               user.getEmail() == null || user.getEmail().isEmpty() ||  
               user.getUsername() == null || user.getUsername().isEmpty() || 
               user.getPassword() == null || user.getPassword().isEmpty();
    }

      private String updateUser(User user, RedirectAttributes redirectAttributes) {
        Optional<User> userOptional = userRepository.findById(user.getId());
        
        if (userOptional.isPresent()) {
            User existingUser = userOptional.get();

            existingUser.setFirstName(user.getFirstName());
            existingUser.setMiddleName(user.getMiddleName());
            existingUser.setLastName(user.getLastName());
            existingUser.setDateOfBirth(user.getDateOfBirth());
            existingUser.setGender(user.getGender());
            existingUser.setEmail(user.getEmail());
            existingUser.setMobileNumber(user.getMobileNumber());

            if (user.getAccess() != null && !user.getAccess().isEmpty()) {
                existingUser.setAccess(user.getAccess());
            }

            if (user.getUsername() != null && !user.getUsername().isEmpty()) {
                existingUser.setUsername(user.getUsername());
            }

            if (user.getPassword() != null && !user.getPassword().isEmpty()) {
                existingUser.setPassword(user.getPassword());
            }

            userRepository.save(existingUser);
            redirectAttributes.addFlashAttribute("message", "User details updated successfully!");
        } else {
            redirectAttributes.addFlashAttribute("error", "User not found.");
        }

        return "redirect:/settings";
    }




      @Autowired
      private JdbcTemplate jdbcTemplate;

      private void fixSequence() {
          try {
              // Dynamically set sequence value to the max ID in the users table
              String query = "SELECT setval('users_id_seq', (SELECT MAX(id) FROM users))";
              jdbcTemplate.execute(query);
              System.out.println("Sequence fixed to the maximum existing ID.");
          } catch (Exception e) {
              e.printStackTrace();
              System.err.println("Error fixing sequence.");
          }
      }

      private String createUser(User user, RedirectAttributes redirectAttributes) {
          try {
              System.out.println("Checking if username already exists...");
              if (userRepository.findByUsername(user.getUsername()).isPresent()) {
                  redirectAttributes.addFlashAttribute("error", "Username already exists.");
                  return "redirect:/allusers";
              }

              System.out.println("Clearing ID to allow auto-increment...");
              user.setId(null); // Ensure PostgreSQL assigns the ID dynamically.

              System.out.println("Saving user...");
              userRepository.save(user);

              // Fix sequence to ensure it knows the new max ID
              fixSequence();

              System.out.println("User successfully saved.");
              userService.registerUser(user);

              redirectAttributes.addFlashAttribute("message", "User added successfully!");
          } catch (Exception e) {
              e.printStackTrace();
              redirectAttributes.addFlashAttribute("error", "Error adding user: " + e.getMessage());
          }

          return "redirect:/allusers";
      }

      


    @PostMapping("/allusers")
    public String searchOrCreateUser(@RequestParam(required = false) String userSearch, 
                                     @ModelAttribute("user") User user, 
                                     Model model, RedirectAttributes redirectAttributes) {
        Long userId = (Long) httpSession.getAttribute("userId");
        Optional<User> adminOptional = userRepository.findById(userId);

        if (adminOptional.isPresent() && "admin".equals(adminOptional.get().getAccess())) {
            if (userSearch != null && !userSearch.isEmpty()) {
                // Search user by criteria
                List<User> users = userService.findUsersByCriteria(userSearch);
                model.addAttribute("users", users);
                
                if (!users.isEmpty()) {
                    model.addAttribute("selectedUser", users.get(0)); 
                } else {
                    model.addAttribute("error", "No users found.");
                }
                return "allusers";
            } else {
                // Attempt to create a new user if no search term is provided
                if (userRepository.findByUsername(user.getUsername()).isPresent()) {
                    redirectAttributes.addFlashAttribute("error", "User already exists with username: " + user.getUsername());
                } else {
                    userService.registerUser(user); // Register user if username does not exist
                    redirectAttributes.addFlashAttribute("message", "User added successfully!");
                }
                return "redirect:/allusers";  // After adding, redirect to all users page
            }
        } else {
            model.addAttribute("errorMessage", "You do not have permission to view all users.");
            return "settings";
        }
    }

    @PostMapping("/registerUser")
    public String registerUser(@ModelAttribute User user, RedirectAttributes redirectAttributes) {
        // Reset the ID to null to ensure a new user is created
        user.setId(null);
        user.setEnabled(true); // Enable user by default
        String message = userService.registerUser(user); // Register user using UserService

        if ("Registration successful".equals(message)) {
            redirectAttributes.addFlashAttribute("message", "User registered successfully!");
            return "redirect:/login"; 
        } else {
            redirectAttributes.addFlashAttribute("error", message);
            return "redirect:/registrationlogin"; 
        }
    }


    @PostMapping("/registrationlogin")
    public String handleLogin1(@RequestParam String username, Model model) {
        Optional<User> userOptional = userRepository.findByUsernameAndEnabled(username, true);
        
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            httpSession.setAttribute("userId", user.getId());
            httpSession.setAttribute("userRole", user.getAccess()); // Store access level in session
            return "redirect:/webpage";
        } else {
            model.addAttribute("error", "User account is disabled.");
            return "registrationlogin"; 
        }
    }

   

}
