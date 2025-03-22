package io._2connect.server.account;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class AccountService {
    private final PasswordEncoder passwordEncoder;
    private final AccountRepository accountRepository;

    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {
        var account = ((Account) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal());

        // check if the current password is correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), account.getPassword())){
            throw new IllegalStateException("Wrong password");
        }

        // check if the two new passwords are the same
        if (!request.getNewPassword().equals(request.getConfirmationPassword())){
            throw new IllegalStateException("Passwords are not the same");
        }

        // update the password
        account.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // save the new password
        accountRepository.save(account);
    }
}
