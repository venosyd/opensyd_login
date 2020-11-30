package com.venosyd.open.login.rest;

import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import com.venosyd.open.commons.util.JSONUtil;
import com.venosyd.open.commons.util.RESTService;
import com.venosyd.open.commons.util.Validators;
import com.venosyd.open.login.Login;
import com.venosyd.open.login.lib.LoginConstants;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
@Path("/")
public class LoginRSImpl implements LoginRS, RESTService {

    @Context
    private HttpHeaders headers;

    @Override
    public Response echo() {
        String message = "LOGIN ECHO GRANTED" + Calendar.getInstance().get(Calendar.YEAR);

        var echoMessage = new HashMap<String, String>();
        echoMessage.put("status", "ok");
        echoMessage.put("message", message);

        return makeResponse(echoMessage);
    }

    @Override
    public Response check(String body) {
        return process(_basicunwrap(body), (request) -> {
            var email = request.get("email");
            var phone = request.get("phone");
            var database = _getdatabase(request);

            var credential = email == null ? phone.replace("\\D+", "") : email;


            var result = Login.check(credential, database);
            return _validateAndProcess(credential, result);
        }, "check");
    }

    @Override
    public Response signup(String body) {
        return process(_loginunwrap(body), (request) -> {
            var email = request.get("email");
            var phone = request.get("phone");
            var passwd = request.get("password");
            var database = _getdatabase(request);

            var credential = email == null ? phone.replace("\\D+", "") : email;

            var result = Login.signup(email, phone, passwd, database);
            return _validateAndProcess(credential, result);
        }, "signup");

    }

    @Override
    public Response oauthSignup(String body) {
        return process(_oauthunwrap(body), (request) -> {
            var email = request.get("email");
            var token = request.get("token");
            var database = _getdatabase(request);

            var result = Login.oauthSignup(email, token, database);
            return _validateAndProcess(email, result);
        }, "oauthSignup");
    }

    @Override
    public Response login(String body) {
        return process(_loginunwrap(body), (request) -> {
            var email = request.get("email");
            var phone = request.get("phone");
            var passwd = request.get("password");
            var database = _getdatabase(request);

            var credential = email == null ? phone.replace("\\D+", "") : email;

            var result = Login.login(credential, passwd, database);
            return _validateAndProcess(email, result);
        }, "login");
    }

    @Override
    public Response oauthLogin(String body) {
        return process(_oauthunwrap(body), (request) -> {
            var email = request.get("email");
            var token = request.get("token");
            var database = _getdatabase(request);

            var result = Login.oauthLogin(email, token, database);
            return _validateAndProcess(email, result);
        }, "oauthLogin");
    }

    @Override
    public Response logout(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var token = request.get("token");
            var database = _getdatabase(request);

            return makeResponse(Login.logout(token, database));
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("token", "database");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response disable(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);

            return makeResponse(Login.disable(credential, database));
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database", "token");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response isEnabled(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);

            return makeResponse(Login.isEnabled(credential, database));
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database", "token");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response enable(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);

            return makeResponse(Login.enable(credential, database));
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database", "token");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response quitall(String body) {
        return process(_basicunwrap(body), (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);

            var result = Login.quitAllSessions(credential, database);
            return _validateAndProcess(credential, result);
        }, "quitall");
    }

    @Override
    public Response requirechange(String body) {
        return process(_basicunwrap(body), (request) -> {
            var email = request.get("email");
            var service = request.get("service");
            service = service == null ? "Venosyd" : service;

            var database = _getdatabase(request);
            var result = Login.requirePasswordChange(service, email, database);

            return _validateAndProcess(email, result);
        }, "requirechange");
    }

    @Override
    public Response change(String body) {
        body = unzip(body);
        Map<String, String> rqst = JSONUtil.fromJSONToMap(body);

        if (rqst.containsKey("hash")) {
            var hash = rqst.get("hash");
            var newpasswd = hash.substring(5, 69);
            var database = hash.substring(69);

            rqst.put("hash", hash.substring(0, 5));
            rqst.put("newpasswd", newpasswd);
            rqst.put("database", database);
        }

        return process(rqst, (request) -> {
            var hash = rqst.get("hash");
            var newpasswd = rqst.get("newpasswd");
            var database = rqst.get("database") == null ? LoginConstants.DB : rqst.get("database");

            return makeResponse(Login.changePassword(hash, newpasswd, database));
        }, "change");
    }

    @Override
    public Response reset(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);

            return makeResponse(Login.resetPassword(credential, database));
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database", "token");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token

    }

    @Override
    public Response changeOldPasswd(String body) {
        body = unzip(body);
        Map<String, String> rqst = JSONUtil.fromJSONToMap(body);

        if (rqst.containsKey("hash")) {
            var hash = rqst.get("hash");

            var token = hash.substring(0, 64);
            var oldpasswd = hash.substring(64, 128);
            var newpasswd = hash.substring(128, 192);
            var database = hash.substring(192);

            rqst.put("token", token);
            rqst.put("database", database);
            rqst.put("oldpasswd", oldpasswd);
            rqst.put("newpasswd", newpasswd);
        }

        var database = rqst.get("database") == null ? LoginConstants.DB : rqst.get("database");

        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var oldpasswd = request.get("oldpasswd");
            var newpasswd = request.get("newpasswd");

            return makeResponse(Login.changeOldPassword(credential, oldpasswd, newpasswd, database));
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "oldpasswd", "newpasswd");

        return authorization != null ? process(rqst, authorization, arguments, operation) // headers
                : process(rqst, operation); // post token
    }

    @Override
    public Response token(String body) {
        body = unzip(body);
        Map<String, String> rqst = JSONUtil.fromJSONToMap(body);

        if (rqst.containsKey("hash")) {
            var hash = rqst.get("hash");

            var token = hash.substring(0, 64);
            var database = hash.substring(64);

            rqst.put("token", token);
            rqst.put("database", database);
        }

        return process(rqst, (request) -> {
            var token = request.get("token");
            var database = _getdatabase(request);

            return makeResponse(Login.verifyToken(token, database));
        }, "token");
    }

    @Override
    public Response uniqueID(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);

            var result = Login.uniqueID(credential, database);
            return _validateAndProcess(credential, result);
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response role(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);
            var role = request.get("role");

            var result = Login.verifyRole(credential, role, database);
            return _validateAndProcess(credential, result);
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database", "role");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response roles(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);

            var result = Login.verifyRoles(credential, database);
            return _validateAndProcess(credential, result);
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response listUsersByRole(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var database = _getdatabase(request);
            var role = request.get("role");

            return makeResponse(Login.listUsersByRole(role, database));
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response giveRole(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var credential = request.get("credential");
            var database = _getdatabase(request);
            var role = request.get("role");

            var result = Login.giveRole(credential, role, database);
            return _validateAndProcess(credential, result);
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database", "role");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    @Override
    public Response removeRole(String body) {
        Function<Map<String, String>, Response> operation = (request) -> {
            var database = _getdatabase(request);
            var credential = request.get("credential");
            var role = request.get("role");

            var result = Login.removeRole(credential, role, database);
            return _validateAndProcess(credential, result);
        };

        var authorization = getauthcode(headers);
        var arguments = Arrays.<String>asList("credential", "database", "role");

        return authorization != null ? process(_unwrap(body, true), authorization, arguments, operation) // headers
                : process(_unwrap(body, false), operation); // post token
    }

    //
    // PRIVATE METHODS
    //

    /**
     * antes de fazer um processamento, realiza uma checkagem de validade das
     * credenciais passadas (fone ou email)
     */
    private Response _validateAndProcess(String credential, Map<String, String> result) {
        if (Validators.Text.validateEmail(credential) || Validators.SpecialChar.validatePhone(credential)) {
            return makeResponse(result);
        } else {
            return makeErrorResponse("nenhum usuario com estas credenciais ainda");
        }
    }

    /** retorna a base de dados do login */
    private String _getdatabase(Map<String, String> request) {
        return request.get("database") == null ? LoginConstants.DB : request.get("database");
    }

    /**
     * desenbrulhamento de funcoes de OAUTH
     */
    private Map<String, String> _oauthunwrap(String body) {
        body = unzip(body);
        var request = JSONUtil.<String, String>fromJSONToMap(body);

        if (request.containsKey("hash")) {
            var hash = request.get("hash");

            var database = hash.substring(0, 32);
            var token = hash.substring(32);

            request.put("database", database);
            request.put("token", token);
        }

        return request;
    }

    /**
     * Desembrulhamento basico
     */
    private Map<String, String> _basicunwrap(String body) {
        body = unzip(body);
        var request = JSONUtil.<String, String>fromJSONToMap(body);

        if (request.containsKey("hash")) {
            var hash = request.get("hash");
            request.put("database", hash);
        }

        return request;
    }

    /**
     * Desembrulhamento para login e signup
     */
    private Map<String, String> _loginunwrap(String body) {
        body = unzip(body);
        var request = JSONUtil.<String, String>fromJSONToMap(body);

        if (request.containsKey("hash")) {
            var hash = request.get("hash");

            String password = hash.substring(0, 64);
            var database = hash.substring(64);

            request.put("password", password);
            request.put("database", database);
        }

        return request;
    }

    /**
     * Desembrulhamento padrao
     */
    private Map<String, String> _unwrap(String body, boolean withouttoken) {
        body = unzip(body);
        var request = JSONUtil.<String, String>fromJSONToMap(body);

        if (request.containsKey("hash")) {
            var hash = request.get("hash");

            String token;
            String database;

            if (withouttoken) {
                database = hash.substring(0);
            } else {
                token = hash.substring(0, 64);
                database = hash.substring(64);

                request.put("token", token);
            }

            database = (database == null || database.isEmpty()) ? LoginConstants.DB : database;
            request.put("database", database);
        }

        return request;
    }

}
