package com.venosyd.open.login.rest;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
@ApplicationPath(LoginRS.LOGIN_BASE_URI)
public class LoginRESTfulAPI extends Application {

    public Set<Class<?>> getClasses() {
        var classes = new HashSet<Class<?>>();
        classes.add(LoginRSImpl.class);

        return classes;
    }
}
