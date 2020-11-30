package com.venosyd.open.login.logic;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.venosyd.open.commons.services.interfaces.Repository;
import com.venosyd.open.commons.services.seeker.ServiceSeeker;
import com.venosyd.open.commons.util.JSONUtil;
import com.venosyd.open.commons.util.RESTService;
import com.venosyd.open.login.lib.LoginConstants;
import com.venosyd.open.login.lib.LoginUtil;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public class RoleBSImpl implements RoleBS {

    @Override
    public Map<String, String> giveRole(String credential, String role, String database) {
        // procura usuario pelo email
        var user = LoginUtil.getAuthUser(credential, database);

        Map<String, String> queryResult = new HashMap<>();

        // se conseguir e o existir token
        if (user != null) {
            user.getRoles().add(role);
            new Repository(database).save(user);

            queryResult.put("status", "ok");
            queryResult.put("payload", "true");
        } else {
            queryResult.put("status", "error");
            queryResult.put("message", "nao foi possivel consultar este authuser");
        }

        return queryResult;
    }

    @Override
    public Map<String, String> removeRole(String credential, String role, String database) {
        // procura usuario pelo email
        var user = LoginUtil.getAuthUser(credential, database);

        Map<String, String> queryResult = new HashMap<>();

        // se conseguir e o existir token
        if (user != null) {
            user.getRoles().remove(role);
            new Repository(database).save(user);

            queryResult.put("status", "ok");
            queryResult.put("payload", "true");
        } else {
            queryResult.put("status", "error");
            queryResult.put("message", "nao foi possivel consultar este authuser");
        }

        return queryResult;
    }

    @Override
    public Map<String, String> listUsersByRole(String role, String database) {
        var headers = new HashMap<String, String>();
        headers.put("Authorization", "Basic " + RESTService.DEFAULT_TOKEN);

        var body = new HashMap<String, Object>();
        body.put("database", LoginConstants.DB);
        body.put("collection", "AuthUser");

        var returned = ServiceSeeker.builder().service("repository").method("post").path("/list").headers(headers)
                .body(body).run();

        if (returned.get("status").equals("ok")) {
            List<String> payload = JSONUtil.fromJSONToList((String) returned.get("payload"));
            List<String> found = new ArrayList<>();

            for (String pay : payload) {
                if (pay.contains(role))
                    found.add(pay);
            }

            Map<String, String> queryResult = new HashMap<>();
            queryResult.put("status", "ok");
            queryResult.put("payload", JSONUtil.toJSON(found));

            return queryResult;
        }

        // se o usuario nao tiver a role perguntada

        Map<String, String> queryResult = new HashMap<>();
        queryResult.put("status", "error");
        queryResult.put("message", "nao foi possivel consultar este authuser");

        return queryResult;
    }

    @Override
    public Map<String, String> verifyRole(String credential, String role, String database) {
        // procura usuario pelo email
        var user = LoginUtil.getAuthUser(credential, database);

        Map<String, String> queryResult = new HashMap<>();

        // se conseguir e o existir token
        if (user != null && user.getRoles() != null && user.getRoles().contains(role)) {
            queryResult.put("status", "ok");
            queryResult.put("payload", "true");
        } else {
            queryResult.put("status", "error");
            queryResult.put("message", "nao autorizado");
        }

        return queryResult;
    }

    @Override
    public Map<String, String> verifyRoles(String credential, String database) {
        // procura usuario pelo email
        var user = LoginUtil.getAuthUser(credential, database);

        var result = new HashMap<String, String>();

        // se conseguir e o existir token
        if (user != null) {
            result.put("status", "ok");
            result.put("payload", JSONUtil.toJSON(user.getRoles()));
            result.put("message", "ROLES INCOMING");
        } else {
            result.put("status", "error");
            result.put("message", "nao foi possivel consultar este authuser");
        }

        return result;
    }

}
