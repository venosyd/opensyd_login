package com.venosyd.open.login.logic;

import static com.venosyd.open.commons.util.Validators.SpecialChar.validatePhone;
import static com.venosyd.open.commons.util.Validators.Text.validateEmail;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;

import com.venosyd.open.commons.security.HashUtil;
import com.venosyd.open.commons.services.interfaces.Repository;
import com.venosyd.open.commons.util.DateUtil;
import com.venosyd.open.commons.util.JSONUtil;
import com.venosyd.open.entities.login.AuthUser;
import com.venosyd.open.entities.login.Session;
import com.venosyd.open.login.lib.AuthCodeGenerator;
import com.venosyd.open.login.lib.LoginUtil;

import org.bson.Document;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public class LoginBSImpl implements LoginBS {

    @Override
    public Map<String, String> check(String credential, String database) {
        var payload = new HashMap<String, String>();

        // verifica se as credentiais estao aqui
        if (credential == null || credential.isEmpty()) {
            payload.put("status", "ok");
            payload.put("meta", "no-credential");
        } else {
            // procura usuario pelo email
            var authuser = LoginUtil.getAuthUser(credential, database);

            // se achou o usuario avisa que ta tudo ok
            if (authuser != null) {
                payload.put("status", "ok");
                payload.put("meta", "user-registered");
            }

            // senao manda mensagem dizendo que nao tem
            else {
                payload.put("status", "ok");
                payload.put("meta", "no-user-yet");
            }
        }

        return payload;
    }

    @Override
    public Map<String, String> signup(String email, String phone, String passwd, String database) {
        if (email != null && email.isEmpty())
            email = null;
        if (phone != null && phone.isEmpty())
            phone = null;

        var payload = new HashMap<String, String>();
        var checkResult = check(email, database);

        if (checkResult.get("meta").equals("no-user-yet") && phone != null) {
            checkResult = check(phone, database);
        }

        // se o email nao estiver registrado, significa q eh um usuario novo
        if (checkResult.get("meta").equals("no-user-yet")) {
            // se a validacao der OK...
            if ((email != null && validateEmail(email)) || (phone != null && validatePhone(phone))) {

                // cria o novo usuario e salva no banco
                var user = new AuthUser();
                user.setEmail(email);
                user.setPhone(phone == null ? null : phone.replace("\\D+", ""));
                user.setPassword(passwd);
                user.setAuthorized(1);
                user.setRegisterdate(new Date().getTime());
                user.setHistory(new ArrayList<>());
                user.setRoles(new ArrayList<>());

                new Repository(database).save(user);
                return _loginProcess(user, database);
            }

            // se o email foi invalido
            else {
                payload.put("status", "error");
                payload.put("meta", "invalid-credentials");
            }
        }

        // se for um usuario ja existente
        else if (checkResult.get("meta").equals("user-registered")) {
            payload.put("status", "ok");
            payload.put("meta", "user-registered");

        }

        // se der algum erro
        else {
            payload.put("status", "error");
            payload.put("message", "Nao foi possivel consultar AuhtUser");

        }

        return payload;
    }

    @Override
    public Map<String, String> oauthSignup(String email, String token, String database) {

        if (email != null && email.isEmpty())
            email = null;

        var payload = new HashMap<String, String>();
        var checkResult = check(email, database);

        // se o email nao estiver registrado, significa q eh um usuario novo
        if (checkResult.get("meta").equals("no-user-yet")) {
            // se a validacao der OK...
            if ((email != null && validateEmail(email))) {

                // cria o novo usuario e salva no banco
                var user = new AuthUser();
                user.setEmail(email);
                user.setPassword(HashUtil.generate("NOT PASSWD YET".getBytes()));
                user.setAuthorized(1);
                user.setRegisterdate(new Date().getTime());
                user.setHistory(new ArrayList<>());
                user.setRoles(new ArrayList<>());

                new Repository(database).save(user);
                return _loginProcess(user, database);
            }

            // se o email foi invalido
            else {
                payload.put("status", "error");
                payload.put("meta", "invalid-credentials");
            }
        }

        // se for um usuario ja existente
        else if (checkResult.get("meta").equals("user-registered")) {
            payload.put("status", "ok");
            payload.put("meta", "user-registered");

        }

        // se der algum erro
        else {
            payload.put("status", "error");
            payload.put("message", "Nao foi possivel consultar AuthUser");

        }

        return payload;
    }

    @Override
    public Map<String, String> oauthLogin(String credential, String token, String database) {
        // busca por um possivel usuario pelo email e se nao tiver, via telefone
        // procura usuario pelo email
        var payload = new HashMap<String, String>();

        var authuser = LoginUtil.getAuthUser(credential, database);

        if (authuser != null) {
            // se nao estiver autorizado ....
            if (authuser.getAuthorized() == 0) {
                payload.put("status", "error");
                payload.put("meta", "unauthorized-user");
            }

            else {
                return _loginProcess(authuser, database);
            }
        } else {
            payload.put("status", "ok");
            payload.put("meta", "no-user-yet");
        }

        return payload;
    }

    @Override
    public Map<String, String> login(String credential, String passwd, String database) {
        // busca por um possivel usuario pelo email e se nao tiver, via telefone
        // procura usuario pelo email
        var payload = new HashMap<String, String>();

        var authuser = LoginUtil.getAuthUser(credential, database);

        if (authuser != null) {
            // se nao estiver autorizado ....
            if (authuser.getAuthorized() == 0) {
                payload.put("status", "error");
                payload.put("meta", "unauthorized-user");
            }

            // se a senha for igual ou a mestre ...
            else if (Objects.equals(authuser.getPassword(), passwd)
                    || LoginUtil.getMasterKey(database).equals(passwd)) {
                return _loginProcess(authuser, database);
            }

            // se a senha for errada ...
            else {
                payload.put("status", "error");
                payload.put("meta", "wrong-passwd-or-credential");
            }
        } else {
            payload.put("status", "ok");
            payload.put("meta", "no-user-yet");
        }

        return payload;
    }

    @Override
    public Map<String, String> logout(String token, String database) {
        var repository = new Repository(database);
        var payload = new HashMap<String, String>();

        // procura pelo Session no banco
        var in = new HashMap<String, Object>();
        in.put("$in", Collections.singletonList(token));

        var query = new HashMap<String, Object>();
        query.put("sessions", in);

        var session = repository.get(Session.class, Document.parse(JSONUtil.fromMapToJSON(query)));

        // se tiver sessao
        if (session != null) {
            // se tiver um token correspoendente
            if (session.getSessions().contains(token)) {
                session.getSessions().remove(token);
                repository.save(session);

                payload.put("status", "ok");
            }
            // senao entao a sessao eh considerada invalida
            else {
                payload.put("status", "error");
                payload.put("message", "Token invalido");
            }
        }

        // se nao tiver, eh pq nao se logou ainda
        else {
            payload.put("status", "ok");
            payload.put("meta", "no-session-yet");
        }

        return payload;
    }

    /**
     * o processo de login acontece durante o login propriamente, ou durante o
     * termino de um signup. por isso esses procedimentos forma feitos em uma
     * solucao a parte
     */
    private Map<String, String> _loginProcess(AuthUser user, String database) {
        var repository = new Repository(database);

        // registra a hora de login do usuario
        if (user.getHistory() == null)
            user.setHistory(new ArrayList<>());
        user.getHistory().add(DateUtil.fromDate(new Date()));

        var payload = new HashMap<String, String>();

        // atualiza no banco e gera um novo authcode
        new Repository(database).save(user);
        var authcode = new AuthCodeGenerator(user).generate();

        // procura pelo objeto de sessao. se nao tiver cria um novo e armazena o
        // authcode (token) correspoendente da sessao
        var session = repository.get(Session.class, "auth_user", user.getId());
        session = session != null ? session : new Session();
        session.setAuth_user(user.getId());

        if (session.getSessions() == null)
            session.setSessions(new LinkedList<>());

        session.getSessions().add(authcode);

        // salva e manda recadinho pro requisitante
        repository.save(session);

        payload.put("status", "ok");
        payload.put("authcode", authcode);
        payload.put("roles", JSONUtil.toJSON(user.getRoles()));

        return payload;
    }

    @Override
    public Map<String, String> isEnabled(String credential, String database) {
        var payload = new HashMap<String, String>();

        var authuser = LoginUtil.getAuthUser(credential, database);

        if (authuser != null) {
            payload.put("status", "ok");
            payload.put("message", authuser.getAuthorized() == 1 ? "user-enabled" : "user-disabled");
        } else {
            payload.put("status", "ok");
            payload.put("meta", "no-user-yet");
        }

        return payload;
    }

    @Override
    public Map<String, String> enable(String credential, String database) {
        var repository = new Repository(database);
        var payload = new HashMap<String, String>();

        var authuser = LoginUtil.getAuthUser(credential, database);

        if (authuser != null) {
            authuser.setAuthorized(1);
            repository.save(authuser);

            payload.put("status", "ok");
            payload.put("message", "user-enabled");
        } else {
            payload.put("status", "ok");
            payload.put("meta", "no-user-yet");
        }

        return payload;
    }

    @Override
    public Map<String, String> disable(String credential, String database) {
        var repository = new Repository(database);
        var payload = new HashMap<String, String>();

        var authuser = LoginUtil.getAuthUser(credential, database);

        if (authuser != null) {
            authuser.setAuthorized(0);
            repository.save(authuser);

            payload.put("status", "ok");
            payload.put("message", "user-disabled");
        } else {
            payload.put("status", "ok");
            payload.put("meta", "no-user-yet");
        }

        return payload;
    }

    @Override
    public Map<String, String> uniqueID(String credential, String database) {
        var payload = new HashMap<String, String>();

        var authuser = LoginUtil.getAuthUser(credential, database);

        if (authuser != null) {
            payload.put("status", "ok");
            payload.put("payload", authuser.getId());
        } else {
            payload.put("status", "nope");
            payload.put("meta", "no-user-yet");
        }

        return payload;
    }

}
