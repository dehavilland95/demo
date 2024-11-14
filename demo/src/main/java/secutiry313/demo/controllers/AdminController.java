package secutiry313.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import secutiry313.demo.models.Role;
import secutiry313.demo.models.User;
import secutiry313.demo.service.RoleService;
import secutiry313.demo.service.UserService;
import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {
    @Autowired
    private UserService userService;
    @Autowired
    private RoleService roleService;

    @GetMapping()
    public String index(Model model) {
        List<User> users = userService.getAll();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        UserDetails user = userService.loadUserByUsername(username);
        List<Role> roles = roleService.getAll();
        model.addAttribute("allRoles", roles);
        if(user != null) {
            model.addAttribute("myInfo", (User) user);
        }
        model.addAttribute("users", users);
        model.addAttribute("user", new User());
        return "admin/index";
    }
    @GetMapping("/show")
    public String show(
            @RequestParam(name = "id", required = false) long id,
            Model model){
        User user = userService.findById(id);
        model.addAttribute("user", user);
        return "admin/show";
    }
    @GetMapping("/new")
    public String newUser(Model model){
        List<Role> roles = roleService.getAll();
        model.addAttribute("roles", roles);
        model.addAttribute("user", new User());
        return "admin/new";
    }
    @PostMapping("/create")
    public String create(@ModelAttribute("user") User user,  @RequestParam(required = false) String[] usersRoles){
        userService.save(user, usersRoles);
        return "redirect:/admin";
    }
    @GetMapping(value = "/edit", params = "id")
    public String edit(
            @RequestParam(name = "id", required = false) long id,
            Model model){
        List<Role> roles = roleService.getAll();
        model.addAttribute("allRoles", roles);
        model.addAttribute("user", userService.findById(id));
        return "admin/edit";
    }
    @PatchMapping("/update")
    public String update(
            @ModelAttribute("user") User user,
            @RequestParam(required = false) String[] usersRoles){
        userService.update(user, usersRoles);
        return "redirect:/admin";
    }
    @DeleteMapping(name = "/delete", params = "id")
    public String delete(@RequestParam(name = "id", required = false) long id){
        userService.delete(id);
        return "redirect:/admin";
    }
}
