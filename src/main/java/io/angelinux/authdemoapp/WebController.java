package io.angelinux.authdemoapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WebController {

    @GetMapping("/")
    public String publicPage() {
        return "Hello world!";
    }

    @GetMapping("/private")
    public String privatePage() {
        return "This should be private 🤔";
    }
}
