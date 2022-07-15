package com.example.authenticationapi.repository;

import com.example.authenticationapi.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    @Query(nativeQuery = true,
            value = "select * from USERS u inner join USER_ROLES ur on u.id = ur.user_id inner join ROLES r on ur.role_id = r.id where r.name=:roleName")
    List<User> findByRoleName(@Param("roleName") String roleName);
}
