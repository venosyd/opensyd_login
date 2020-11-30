package com.venosyd.open.login.logic;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.venosyd.open.commons.services.interfaces.Repository;
import com.venosyd.open.commons.util.JSONUtil;
import com.venosyd.open.entities.login.AuthUser;
import com.venosyd.open.entities.login.Session;
import com.venosyd.open.login.lib.LoginConstants;
import com.venosyd.open.login.lib.LoginUtil;

import org.bson.Document;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public class SessionBSImpl implements SessionBS {

    @Override
    public Map<String, String> quitAllSessions(String credential, String database) {
        var repository = new Repository(database);
        // procura usuario pelo email
        var authuser = LoginUtil.getAuthUser(credential, database);

        var payload = new HashMap<String, String>();

        // procura pelo Session no banco
        var session = repository.get(Session.class, "auth_user", authuser.getId());

        // se conseguir e o existir token
        if (session != null) {
            // invalida o token da sessao caracterizando o logoff
            session.setSessions(new ArrayList<>());
            repository.save(session);

            payload.put("status", "ok");
        }

        // se nao retornar sessao ou nao tiver token, retorna mensagem dizendo que o
        // token eh invalido
        else {
            payload.put("status", "error");
            payload.put("message", "Token Invalido");
        }

        return payload;
    }

    @Override
    public Map<String, String> verifyToken(String token, String database) {
        var repository = new Repository(database);
        var payload = new HashMap<String, String>();

        if (token.equals(LoginConstants.TOKEN)) {
            payload.put("status", "ok");
            return payload;
        }

        // procura pelo Session no banco
        var in = new HashMap<String, Object>();
        in.put("$in", Collections.singletonList(token));

        var query = new HashMap<String, Object>();
        query.put("sessions", in);

        var session = repository.get(Session.class, Document.parse(JSONUtil.fromMapToJSON(query)));

        // se conseguir e o existir token
        if (session != null && session.getSessions().contains(token)) {
            // salva a atualizacao no banco
            var user = repository.get(AuthUser.class, session.getAuth_user());

            payload.put("status", "ok");
            payload.put("email", ((AuthUser) user).getEmail());
            payload.put("phone", ((AuthUser) user).getPhone());
        }

        // se nao retornar sessao ou nao tiver token, retorna mensagem dizendo que o
        // token eh invalido
        else {
            payload.put("status", "error");
            payload.put("message", "Token Invalido");
        }

        return payload;
    }

}
