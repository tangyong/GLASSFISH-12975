package org.glassfish.osgi.felixwebconsoleextension;

import java.security.PrivilegedAction;

import javax.security.auth.Subject;

import org.apache.felix.webconsole.WebConsoleSecurityProvider;
import com.sun.enterprise.security.auth.login.LoginContextDriver;
import com.sun.enterprise.security.auth.login.common.PasswordCredential;
import com.sun.enterprise.security.common.AppservAccessController;

public class GlassFishSecurityProvider implements WebConsoleSecurityProvider {

	// Todo: Should get the realm from domain.xml for supporting pluggable
	// But, seem not that GlassFishSecurityProvider can not get HK2 component
	// need to consult sahoo.
	private static String ADMIN_REALM = "admin-realm";

	@Override
	public Object authenticate(String username, String password) {
		final Subject fs = new Subject();
        final PasswordCredential pc =
            new PasswordCredential(username, password.toCharArray(), ADMIN_REALM);
        
        AppservAccessController.doPrivileged(new PrivilegedAction(){
            public java.lang.Object run(){
                fs.getPrivateCredentials().add(pc);
                return fs;
            }
        });

        LoginContextDriver.login(fs, PasswordCredential.class);
        
        return fs;
	}

	@Override
	public boolean authorize(Object user, String role) {
		// TODO Auto-generated method stub
		return false;
	}
}
