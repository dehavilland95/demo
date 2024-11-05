package secutiry313.demo.utils;

import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import secutiry313.demo.models.User;
import secutiry313.demo.service.UserService;


@Component
public class PersonValidator implements Validator {

    private final UserService userService;
    public PersonValidator(UserService userService) {
        this.userService = userService;
    }
    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        User user = (User) target;
        try {
            userService.loadUserByUsername(user.getUsername());
        }catch (Exception e) {
            return;
        }
        errors.rejectValue("username", null, "Аккаунт с таким имейлом уже существует");
    }
}
