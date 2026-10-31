package com.piiguard.vault;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface VaultRepository extends JpaRepository<VaultEntry, Long> {
    Optional<VaultEntry> findByValueHmac(String valueHmac);
    Optional<VaultEntry> findByToken(String token);
}
