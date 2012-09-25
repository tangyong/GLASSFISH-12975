/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2012 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://glassfish.dev.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */

package org.glassfish.osgi.felixwebconsoleextension;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.felix.webconsole.WebConsoleSecurityProvider2;
import org.glassfish.embeddable.GlassFish;
import org.glassfish.embeddable.GlassFishException;
import org.glassfish.security.services.api.authentication.AuthenticationService;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpContext;

/**
* This class extends WebConsoleSecurityProvider2 to support the security of Glassfish 
* OSGi Admin Console.See http://felix.apache.org/site/web-console-security-provider.html#
* WebConsoleSecurityProvider-WebConsoleSecurityProvider2 for more details.
*
* @author Tang Yong(tangyong@cn.fujitsu.com)
*/
public class GlassFishSecurityProvider implements WebConsoleSecurityProvider2 {

	private static final String HEADER_AUTHORIZATION = "Authorization";
	private static final String AUTHENTICATION_SCHEME_BASIC = "Basic";
	private static final String HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";
	private BundleContext ctx;
	private GlassFish gf;

	private String realm; //improve it later on

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public void setBundleContext(BundleContext context) {
		ctx = context;
	}

	private GlassFish getGlassFish() {
		GlassFish gf = (GlassFish) ctx.getService(ctx.getServiceReference(GlassFish.class.getName()));
		try {
			assert (gf.getStatus() == GlassFish.Status.STARTED);
		} catch (GlassFishException e) {
			throw new RuntimeException(e); // TODO: Proper Exception Handling
		}
		return gf;
	}

	public Subject doAuthenticate(String username, String password) {
		gf = getGlassFish();
		AuthenticationService authService = null;
		try {
			authService = gf.getService(AuthenticationService.class);
		} catch (GlassFishException gfe) {
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
	public Object authenticate(String username, String password) {
		return doAuthenticate(username, password);
	}

	@Override
	public boolean authenticate(HttpServletRequest request,
			HttpServletResponse response) {
		// Return immediately if the header is missing
		String authHeader = request.getHeader(HEADER_AUTHORIZATION);
		if (authHeader != null && authHeader.length() > 0) {

			// Get the authType (Basic, Digest) and authInfo (user/password)
			// from the header
			authHeader = authHeader.trim();
			int blank = authHeader.indexOf(' ');
			if (blank > 0) {
				String authType = authHeader.substring(0, blank);
				String authInfo = authHeader.substring(blank).trim();

				// Check whether authorization type matches
				if (authType.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
					try {
						String srcString = base64Decode(authInfo);
						int i = srcString.indexOf(':');
						String username = srcString.substring(0, i);
						String password = srcString.substring(i + 1);

						// authenticate
						Subject subject = doAuthenticate(username, password);
						if (subject != null) {
							// as per the spec, set attributes
							request.setAttribute(
									HttpContext.AUTHENTICATION_TYPE,
									HttpServletRequest.BASIC_AUTH);
							request.setAttribute(HttpContext.REMOTE_USER,
									username);

							// set web console user attribute
							request.setAttribute(
									WebConsoleSecurityProvider2.USER_ATTRIBUTE,
									username);

							// succeed
							return true;
						}
					} catch (Exception e) {
						// Ignore
					}
				}
			}
		}

		// request authentication
		try {
			response.setHeader(HEADER_WWW_AUTHENTICATE,
					AUTHENTICATION_SCHEME_BASIC + " realm=\"" + this.realm
							+ "\"");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.setContentLength(0);
			response.flushBuffer();
		} catch (IOException ioe) {
			// failed sending the response ... cannot do anything about it
		}

		// inform HttpService that authentication failed
		return false;
	}

	@Override
	public boolean authorize(Object o, String s) {
		return true;
	}

	private static String base64Decode(String srcString) {
		byte[] transformed = Base64.decodeBase64(srcString);
		try {
			return new String(transformed, "ISO-8859-1");
		} catch (UnsupportedEncodingException uee) {
			return new String(transformed);
		}
	}
}
