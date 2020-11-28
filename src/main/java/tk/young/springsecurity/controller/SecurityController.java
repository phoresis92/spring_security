package tk.young.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping
    public String test () {
        return "home";
    }

    @GetMapping("loginPage")
    public String loginPage(){
        return "loginPage";
    }

}
