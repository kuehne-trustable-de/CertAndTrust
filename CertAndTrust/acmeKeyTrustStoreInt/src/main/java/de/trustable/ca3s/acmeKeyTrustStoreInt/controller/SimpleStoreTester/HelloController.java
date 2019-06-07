package de.trustable.ca3s.storeTester.controller.SimpleStoreTester;

import org.springframework.web.bind.annotation.RestController;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

import org.springframework.web.bind.annotation.RequestMapping;

@RestController
public class HelloController {

	public HelloController() {
		System.out.println("HelloController cTor");
	}
	
	@RequestMapping(value = "/foo", method = GET)
    public String index() {
        return "SimpleStoreTester accessable!";
    }

}