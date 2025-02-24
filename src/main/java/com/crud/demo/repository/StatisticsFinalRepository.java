package com.crud.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import com.crud.demo.model.User;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByUsernameAndEnabled(String username, boolean enabled);
    Optional<User> findById(Long id);
    Optional<User> findByUsernameOrEmailAndPassword(String username, String email, String password);
    
    @Query("SELECT u FROM User u WHERE (LOWER(u.username) = LOWER(:identifier) OR LOWER(u.email) = LOWER(:identifier)) AND u.password = :password")
    Optional<User> findByUsernameOrEmailIgnoreCaseAndPassword(String identifier, String password);
    // This method allows for searching users based on first name.
    List<User> findByFirstNameContainingIgnoreCase(String userSearch);

    // This method allows for searching users based on multiple criteria.
    List<User> findByFirstNameContainingOrLastNameContainingOrEmailContainingOrMobileNumberContainingOrUsernameContaining(
            String firstName, String lastName, String email, String mobileNumber, String username);

    // New method to find users by access level (e.g., "User", "Admin", "Manager").
    List<User> findByAccess(String access);

    // New method to search by multiple criteria, including access level.
    List<User> findByFirstNameContainingOrLastNameContainingOrEmailContainingOrMobileNumberContainingOrUsernameContainingAndAccess(
            String firstName, String lastName, String email, String mobileNumber, String username, String access);

    

    
}

