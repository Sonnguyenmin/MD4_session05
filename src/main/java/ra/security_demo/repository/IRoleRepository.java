package ra.security_demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ra.security_demo.constants.RoleName;
import ra.security_demo.model.Roles;

import java.util.Optional;

@Repository
public interface IRoleRepository extends JpaRepository<Roles, Long> {
    Optional<Roles> findByRoleName(RoleName roleName);
}
