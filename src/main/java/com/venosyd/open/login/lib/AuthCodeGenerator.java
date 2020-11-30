package com.venosyd.open.login.lib;

import java.util.Calendar;

import com.venosyd.open.commons.security.HashUtil;
import com.venosyd.open.commons.util.RandomUtil;
import com.venosyd.open.entities.login.AuthUser;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public class AuthCodeGenerator {

    private AuthUser user;

    public AuthCodeGenerator(AuthUser user) {
        this.user = user;
    }

    public String generate() {
        var today = Calendar.getInstance();

        var token = '#' + today.get(Calendar.YEAR) + '#' + today.get(Calendar.MONTH) + '#'
                + today.get(Calendar.DAY_OF_MONTH) + '#' + today.get(Calendar.HOUR) + '#' + today.get(Calendar.MINUTE)
                + '#' + today.get(Calendar.SECOND) + '#' + user.getEmail() + RandomUtil.nextInt(100000, 2000000000)
                + RandomUtil.nextInt(100000, 2000000000) + RandomUtil.nextInt(100000, 2000000000)
                + RandomUtil.nextInt(100000, 2000000000) + RandomUtil.nextInt(100000, 2000000000);

        return HashUtil.generate(token.getBytes());
    }

}
