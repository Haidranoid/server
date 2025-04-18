package io._2connect.server.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Integer> {
    @Query("""
    select t from Token t inner join Account a on t.account.id = a.id
    where a.id = :accountId and (t.expired = false or t.revoked = false)
    """)
    List<Token> findAllValidTokensByAccount(Integer accountId);

    Optional<Token> findByToken(String token);
}
