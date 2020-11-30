package com.venosyd.open.login;

import java.util.Map;

import com.venosyd.open.login.logic.LoginBS;
import com.venosyd.open.login.logic.PasswdBS;
import com.venosyd.open.login.logic.RoleBS;
import com.venosyd.open.login.logic.SessionBS;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public abstract class Login {

    public static Map<String, String> check(String credential, String database) {
        return LoginBS.INSTANCE.check(credential, database);
    }

    public static Map<String, String> signup(String email, String phone, String passwd, String database) {
        return LoginBS.INSTANCE.signup(email, phone, passwd, database);
    }

    public static Map<String, String> oauthSignup(String email, String token, String database) {
        return LoginBS.INSTANCE.oauthSignup(email, token, database);
    }

    public static Map<String, String> login(String credential, String passwd, String database) {
        return LoginBS.INSTANCE.login(credential, passwd, database);
    }

    public static Map<String, String> oauthLogin(String email, String token, String database) {
        return LoginBS.INSTANCE.oauthLogin(email, token, database);
    }

    public static Map<String, String> logout(String token, String database) {
        return LoginBS.INSTANCE.logout(token, database);
    }

    public static Map<String, String> isEnabled(String credential, String database) {
        return LoginBS.INSTANCE.isEnabled(credential, database);
    }

    public static Map<String, String> enable(String credential, String database) {
        return LoginBS.INSTANCE.enable(credential, database);
    }

    public static Map<String, String> disable(String credential, String database) {
        return LoginBS.INSTANCE.disable(credential, database);
    }

    public static Map<String, String> uniqueID(String credential, String database) {
        return LoginBS.INSTANCE.uniqueID(credential, database);
    }

    public static Map<String, String> quitAllSessions(String credencial, String database) {
        return SessionBS.INSTANCE.quitAllSessions(credencial, database);
    }

    public static Map<String, String> verifyToken(String token, String database) {
        return SessionBS.INSTANCE.verifyToken(token, database);
    }

    public static boolean isAuthorized(String token, String database) {
        var response = verifyToken(token, database);
        return response.get("status").equals("ok");
    }

    public static Map<String, String> requirePasswordChange(String service, String email, String database) {
        return PasswdBS.INSTANCE.requirePasswordChange(service, email, database);
    }

    public static Map<String, String> changePassword(String hash, String newpasswd, String database) {
        return PasswdBS.INSTANCE.changePassword(hash, newpasswd, database);
    }

    public static Map<String, String> resetPassword(String credential, String database) {
        return PasswdBS.INSTANCE.resetPassword(credential, database);
    }

    public static Map<String, String> changeOldPassword(String credential, String oldpasswd, String newpasswd,
            String database) {
        return PasswdBS.INSTANCE.changeOldPassword(credential, oldpasswd, newpasswd, database);
    }

    public static Map<String, String> verifyRole(String credential, String role, String database) {
        return RoleBS.INSTANCE.verifyRole(credential, role, database);
    }

    public static Map<String, String> verifyRoles(String credential, String database) {
        return RoleBS.INSTANCE.verifyRoles(credential, database);
    }

    public static Map<String, String> listUsersByRole(String role, String database) {
        return RoleBS.INSTANCE.listUsersByRole(role, database);
    }

    public static Map<String, String> giveRole(String credential, String role, String database) {
        return RoleBS.INSTANCE.giveRole(credential, role, database);
    }

    public static Map<String, String> removeRole(String credential, String role, String database) {
        return RoleBS.INSTANCE.removeRole(credential, role, database);
    }
}
