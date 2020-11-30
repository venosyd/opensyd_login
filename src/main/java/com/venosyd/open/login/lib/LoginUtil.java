package com.venosyd.open.login.lib;

import com.venosyd.open.commons.log.Debuggable;
import com.venosyd.open.commons.services.interfaces.Repository;
import com.venosyd.open.entities.login.AuthUser;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public class LoginUtil implements Debuggable {

    /** retorna um usuario pela usa credencial (email ou telefone) */
    public static AuthUser getAuthUser(String credential, String database) {
        var repository = new Repository(database);

        var authuser = repository.get(AuthUser.class, "email", credential);

        // se nao tiver, procura pelo telefone
        if (authuser == null) {
            credential = credential.replace("\\D+", "");

            authuser = repository.get(AuthUser.class, "phone", credential);
        }

        return authuser;
    }

    public static String getMasterKey(String database) {
        var repository = new Repository(database);
        var admin = repository.get(AuthUser.class, "phone", "900000000");

        if (admin == null)
            return "";

        return admin.getPassword();
    }

}
