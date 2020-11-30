package com.venosyd.open.login.logic;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import com.venosyd.open.commons.log.Debuggable;
import com.venosyd.open.commons.services.interfaces.Mail;
import com.venosyd.open.commons.services.interfaces.Repository;
import com.venosyd.open.commons.util.Config;
import com.venosyd.open.entities.login.AuthUser;
import com.venosyd.open.login.lib.LoginChangePasswd;
import com.venosyd.open.login.lib.LoginConstants;
import com.venosyd.open.login.lib.LoginUtil;

/**
 * @author sergio lisan <sels@venosyd.com>
 */
public class PasswdBSImpl implements PasswdBS, Debuggable {

    /// dicionario de solicitacoes de recuperacao de senha
    /// hash / email
    private Map<String, String> _recoveryMap;

    PasswdBSImpl() {
        _recoveryMap = new ConcurrentHashMap<>();
    }

    @Override
    public Map<String, String> requirePasswordChange(String service, String email, String database) {
        var result = new HashMap<String, String>();
        var user = new Repository(database).get(AuthUser.class, "email", email);

        // se existe usuario
        if (user != null) {
            var hash = UUID.randomUUID().toString().substring(0, 5);
            _recoveryMap.put(hash, email);

            var message = _sendChangePasswdEmail(email, service, hash);

            result.put("status", Objects.equals(message, "email enviado com sucesso") ? "ok" : "error");
            result.put("message", message);
        }

        // se nao retornar o usuario, entao ele nao esta cadastrado
        else {
            result.put("status", "error");
            result.put("message", "nenhum usuario com estas credenciais ainda");
        }

        return result;
    }

    @Override
    public Map<String, String> changePassword(String hash, String newpasswd, String database) {
        var repository = new Repository(database);
        var result = new HashMap<String, String>();

        if (_recoveryMap.containsKey(hash)) {
            var email = _recoveryMap.get(hash);

            var user = repository.get(AuthUser.class, "email", email);

            // se tiver authuser
            if (user != null) {
                user.setPassword(newpasswd);
                repository.save(user);

                _recoveryMap.remove(hash);

                // se der certo a atualizacao
                if (user instanceof AuthUser) {
                    result.put("status", "ok");
                    result.put("message", "senha trocada com sucesso");

                }
                // se acontecer algum erro no update
                else {
                    result.put("status", "error");
                    result.put("message", "nao foi possivel consultar este authuser");
                }
            }

            // se o usuario nao existir
            else {
                result.put("status", "error");
                result.put("message", "nao foi possivel mudar a senha");
            }
        }

        // se o link estiver expirado
        else {
            result.put("status", "error");
            result.put("message", "link expirado");
        }

        return result;
    }

    @Override
    public Map<String, String> resetPassword(String credential, String database) {

        // busca por um possivel usuario pelo email e se nao tiver, via telefone
        var user = LoginUtil.getAuthUser(credential, database);

        var result = new HashMap<String, String>();

        if (user != null) {
            user.setPassword("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
            new Repository(database).save(user);

            result.put("status", "ok");
            result.put("message", "senha trocada com sucesso");
        }

        // se o usuario nao existir
        else {
            result.put("status", "error");
            result.put("meta", "no-user-yet");
        }

        return result;
    }

    @Override
    public Map<String, String> changeOldPassword(String credential, String oldpasswd, String newpasswd,
            String database) {

        // busca por um possivel usuario pelo email e se nao tiver, via telefone
        var user = LoginUtil.getAuthUser(credential, database);

        var result = new HashMap<String, String>();

        if ((user instanceof AuthUser) && (((AuthUser) user).getPassword().equals(oldpasswd))) {
            user.setPassword(newpasswd);
            new Repository(database).save(user);

            result.put("status", "ok");
            result.put("message", "senha trocada com sucesso");
        }

        // se o usuario nao existir
        else {
            result.put("status", "error");
            result.put("message", "nao foi possivel mudar a senha");
        }

        return result;
    }

    /**
     * send a message to user for password change
     */
    @SuppressWarnings("rawtypes")
    private String _sendChangePasswdEmail(String email, String service, String hash) {
        var payload = new LoginChangePasswd().getPayload(service, hash);
        var passwd = ((Map) Config.INSTANCE.get("mail")).get("auth");
        var from = ((Map) Config.INSTANCE.get("mail")).get("login");
        var message = new HashMap<String, Object>();

        message.put("title", service + " - Mudar a senha");
        message.put("from", from);
        message.put("fromName", service);
        message.put("hash", LoginConstants.DB + passwd);
        message.put("emails", "[" + email + "]");
        message.put("payload", payload);

        var response = Mail.send(message);

        if (response.get("status").equals("ok")) {
            return "senha trocada com sucesso";
        } else {
            return "problemas ao mudar a senha" + ": " + response.get("details");
        }
    }

}
