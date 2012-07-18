package org.glassfish.osgi.felixwebconsoleextension;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.apache.felix.webconsole.WebConsoleSecurityProvider;
import org.glassfish.embeddable.GlassFish;
import org.glassfish.embeddable.GlassFishException;
import org.glassfish.security.services.api.authentication.AuthenticationService;
import org.osgi.framework.BundleContext;

public class GlassFishSecurityProvider implements WebConsoleSecurityProvider {
	
	private BundleContext ctx;
	private GlassFish gf;
	
	public void setBundleContext(BundleContext context){
		ctx = context;
	}
	
	 private GlassFish getGlassFish() {
         GlassFish gf = (GlassFish) ctx.getService(ctx.getServiceReference(GlassFish.class.getName()));
         try {
             assert(gf.getStatus() == GlassFish.Status.STARTED);
         } catch (GlassFishException e) {
             throw new RuntimeException(e); // TODO(Sahoo): Proper Exception Handling
         }
         return gf;
     }

	@Override
	public Object authenticate(String username, String password) {
		gf = getGlassFish();
		AuthenticationService authService = null;
		try{
		    authService = gf.getService(AuthenticationService.class);
		}catch(GlassFishException gfe){
			gfe.printStackTrace();
			return null;
		}

        Subject fs = null;

       try {
    	   fs = authService.login(username, password.toCharArray(), fs);
        } catch (LoginException e) {			
          e.printStackTrace();
          return null;
        }

          return fs;		
	}

	@Override
	public boolean authorize(Object user, String role) {
		// TODO Auto-generated method stub
		return false;
	}
}
