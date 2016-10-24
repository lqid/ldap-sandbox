import org.ldaptive.*;
import org.ldaptive.auth.*;
import org.ldaptive.auth.ext.ActiveDirectoryAuthenticationResponseHandler;
import org.ldaptive.pool.BlockingConnectionPool;
import org.ldaptive.pool.PooledConnectionFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LdapSandbox {
    private final static Logger logger = LoggerFactory.getLogger(LdapSandbox.class);

    public static void main(String[] args) throws Exception {
        setupConnection();
    }

    private static void setupConnection() throws LdapException {
        ConnectionConfig connConfig = new ConnectionConfig("ldap://db.debian.org:389");
        connConfig.setUseStartTLS(true);
        BlockingConnectionPool pool = new BlockingConnectionPool(new DefaultConnectionFactory(connConfig));
        pool.initialize();
        PooledConnectionFactory connFactory = new PooledConnectionFactory(pool);
        Connection conn = connFactory.getConnection();

        try {
            conn.open();
            if (conn.isOpen()) {
                logger.info("Connection to LDAP server is successful.");
            }
            SearchOperation search = new SearchOperation(conn);
            SearchResult result = search.execute(
                    new SearchRequest(
                            "ou=users,dc=debian,dc=org", "(uid=fh)")).getResult();
            result.getEntry();
        } catch (LdapException e) {
            logger.error(e.getMessage());
        } finally {
            conn.close();
            logger.info("Connection to LDAP server has closed.");
        }
    }

    private static void authenticateUser() throws LdapException {
        ConnectionConfig connConfig = new ConnectionConfig("ldap://db.debian.org:389");
        connConfig.setUseStartTLS(true);
        SearchDnResolver dnResolver = new SearchDnResolver(new DefaultConnectionFactory(connConfig));
        dnResolver.setBaseDn("ou=people,dc=debian,dc=org");
        dnResolver.setUserFilter("uid={user}");
        BindAuthenticationHandler authHandler = new BindAuthenticationHandler(new DefaultConnectionFactory(connConfig));
        Authenticator auth = new Authenticator(dnResolver, authHandler);
        auth.setAuthenticationResponseHandlers(new ActiveDirectoryAuthenticationResponseHandler());
        auth.setReturnAttributes(ActiveDirectoryAuthenticationResponseHandler.ATTRIBUTES);
        AuthenticationResponse response = auth.authenticate(new AuthenticationRequest("fh", new Credential("password")));
        if (response.getResult()) {
            // authentication succeeded, AD does not support warnings
        } else {
            // authentication failed, check account state
            AccountState state = response.getAccountState();
            // authentication failed, only an error should exist
            AccountState.Error error = state.getError();
        }
    }

}
