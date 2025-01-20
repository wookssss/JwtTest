package JwtTest.repository;

import JwtTest.entity.JwtUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<JwtUser, Long> {
    Boolean existsByUsername(String username);
    JwtUser findByUsername(String username);
}
