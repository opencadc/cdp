/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2017.                            (c) 2017.
*  Government of Canada                 Gouvernement du Canada
*  National Research Council            Conseil national de recherches
*  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
*  All rights reserved                  Tous droits réservés
*
*  NRC disclaims any warranties,        Le CNRC dénie toute garantie
*  expressed, implied, or               énoncée, implicite ou légale,
*  statutory, of any kind with          de quelque nature que ce
*  respect to the software,             soit, concernant le logiciel,
*  including without limitation         y compris sans restriction
*  any warranty of merchantability      toute garantie de valeur
*  or fitness for a particular          marchande ou de pertinence
*  purpose. NRC shall not be            pour un usage particulier.
*  liable in any event for any          Le CNRC ne pourra en aucun cas
*  damages, whether direct or           être tenu responsable de tout
*  indirect, special or general,        dommage, direct ou indirect,
*  consequential or incidental,         particulier ou général,
*  arising from the use of the          accessoire ou fortuit, résultant
*  software.  Neither the name          de l'utilisation du logiciel. Ni
*  of the National Research             le nom du Conseil National de
*  Council of Canada nor the            Recherches du Canada ni les noms
*  names of its contributors may        de ses  participants ne peuvent
*  be used to endorse or promote        être utilisés pour approuver ou
*  products derived from this           promouvoir les produits dérivés
*  software without specific prior      de ce logiciel sans autorisation
*  written permission.                  préalable et particulière
*                                       par écrit.
*
*  This file is part of the             Ce fichier fait partie du projet
*  OpenCADC project.                    OpenCADC.
*
*  OpenCADC is free software:           OpenCADC est un logiciel libre ;
*  you can redistribute it and/or       vous pouvez le redistribuer ou le
*  modify it under the terms of         modifier suivant les termes de
*  the GNU Affero General Public        la “GNU Affero General Public
*  License as published by the          License” telle que publiée
*  Free Software Foundation,            par la Free Software Foundation
*  either version 3 of the              : soit la version 3 de cette
*  License, or (at your option)         licence, soit (à votre gré)
*  any later version.                   toute version ultérieure.
*
*  OpenCADC is distributed in the       OpenCADC est distribué
*  hope that it will be useful,         dans l’espoir qu’il vous
*  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
*  without even the implied             GARANTIE : sans même la garantie
*  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
*  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
*  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
*  General Public License for           Générale Publique GNU Affero
*  more details.                        pour plus de détails.
*
*  You should have received             Vous devriez avoir reçu une
*  a copy of the GNU Affero             copie de la Licence Générale
*  General Public License along         Publique GNU Affero avec
*  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
*  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
*                                       <http://www.gnu.org/licenses/>.
*
*  $Revision: 5 $
*
************************************************************************
*/

package ca.nrc.cadc.cred.client;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.AuthorizationToken;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.SSOCookieCredential;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;

import java.io.File;
import java.net.URI;
import java.security.AccessControlException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.security.auth.Subject;

import org.apache.log4j.Logger;

/**
 * Utility class to support a standard server-side use of the CredClient.
 * Server-side applications typically have to have valid credentials for the
 * current user in order to call other services on the user's behalf. The
 * methods here support the standard usage as follows:
 * <ul>
 * <li>check Subject for a valid proxy certificate
 * <li>discard stored but invalid certificate
 * <li>load certificate for ops user from${user.home}/.ssl/cadcproxy.pem
 * <li>use CredClient as ops user to retrieve a new proxy certificate for the
 * current user
 * <li>store the user certificate in the Subject
 * </ul>
 * 
 * @author pdowler
 */
public class CredUtil {
    private static final Logger log = Logger.getLogger(CredUtil.class);

    public static final double PROXY_CERT_DURATION = 0.1; // couple of hours
    public static final String SERVOPS_JNDI_NAME = "servops-cert";

    private CredUtil() {
    }

    public static Subject createOpsSubject() {
        Subject s = createServopsSubjectFromJNDI();
        log.debug("servops subject from JNDI: " + s);
        if (s == null) {
            s = createServopsSubjectFromFile();
            log.debug("servops subject from disk: " + s);
        }
        
        if (s != null) {
            X509CertificateChain ops = X509CertificateChain.findPrivateKeyChain(s.getPublicCredentials());
            try {
                ops.getChain()[0].checkValidity();
            } catch (Exception ex) {
                throw new RuntimeException("CONFIG: servops certificate is invalid", ex);
            }
            return s;
        }

        throw new IllegalStateException("servops.pem not found in JNDI or on disk.");
    }

    private static Subject createServopsSubjectFromJNDI() {
        try {
            InitialContext ic = new InitialContext();
            Object entry = ic.lookup(SERVOPS_JNDI_NAME);
            if (entry == null)
                return null;
            X509CertificateChain chain = (X509CertificateChain) entry;
            return AuthenticationUtil.getSubject(chain);
        } catch (NameNotFoundException e) {
            return null;
        } catch (NamingException e) {
            log.warn("Unexpected JNDI exception.", e);
            return null;
        }
    }

    private static Subject createServopsSubjectFromFile() {
        File pemFile = new File(System.getProperty("user.home") + "/.ssl/cadcproxy.pem");
        return SSLUtil.createSubject(pemFile);
    }

    /**
     * Check if the current subject has usable credentials (a valid X509 proxy
     * certificate) and call the local CDP service if necessary.
     * 
     * @return true if subject has valid credentials, false if subject is anonymous
     * @throws AccessControlException
     * @throws java.security.cert.CertificateExpiredException
     * @throws java.security.cert.CertificateNotYetValidException
     */
    public static boolean checkCredentials()
            throws AccessControlException, CertificateExpiredException, CertificateNotYetValidException {
        return checkCredentials(AuthenticationUtil.getCurrentSubject());
    }

    /**
     * Check if the specified subject has usable credentials (a valid X509 proxy
     * certificate) and call the local CDP service if necessary. This method uses
     * the <code>ca.nrc.cadc.reg.client.LocalAuthority</code> class to find the
     * local CDP service. Thus, this usage only makes sense in server-side
     * applications.
     * 
     * @param subject the subject to check
     * @return true if subject has valid credentials, false if subject is anonymous
     * @throws java.security.cert.CertificateExpiredException
     * @throws java.security.cert.CertificateNotYetValidException
     */
    public static boolean checkCredentials(final Subject subject)
            throws AccessControlException, CertificateExpiredException, CertificateNotYetValidException {

        if (subject == null) {
            return false;
        }
        
        // 
        // TODO: a cookie is only valid for a single domain, but we don't know what the caller
        // intends to do so we can't actually determine if they have an SSOCookieCredential for that
        log.debug("check for valid cookie credentials...");
        Set<SSOCookieCredential> cookieCreds = subject.getPublicCredentials(SSOCookieCredential.class);
        for (SSOCookieCredential nextCookie : cookieCreds) {
            log.debug("Checking cookie credential: " + nextCookie);
            if (!nextCookie.isExpired()) {
                return true;
            }
        }
        log.debug("... no valid cookies"); 
        
        // TODO: check domains
        log.debug("check for auth tokens...");
        Set<AuthorizationToken> tokens = subject.getPublicCredentials(AuthorizationToken.class);
        if (!tokens.isEmpty()) {
            return true;
        }
        log.debug("... no tokens"); 
        
        log.debug("check for a valid X509CertificateChain...");
        X509CertificateChain privateKeyChain = X509CertificateChain.findPrivateKeyChain(subject.getPublicCredentials());
        if (privateKeyChain != null) {
            try {
                privateKeyChain.getChain()[0].checkValidity();
                return true;
            } catch (CertificateException ex) {
                log.debug("invalid X509CertificateChain: removing"); 
                privateKeyChain = null; // get new one below
            }
        }
        log.debug("... no valid X509CertificateChain"); 
        
        // get a valid proxy cert from local CDP service: requires an identity
        if (subject.getPrincipals().isEmpty()) {
            log.debug("no principals: return false"); 
            return false;
        }
        
        LocalAuthority loc = new LocalAuthority();
        URI credURI;
        try {
            credURI = loc.getServiceURI(Standards.CRED_PROXY_10.toASCIIString());
        } catch (NoSuchElementException ex) {
            log.debug("checkCredentials: no local CDP service " + Standards.CRED_PROXY_10 + " in LocalAuthority");
            return false;
        }
        // just in case LocalAuthority changes to return null (TBD)
        if (credURI == null) {
            log.debug("checkCredentials: no local CDP service " + Standards.CRED_PROXY_10 + " in LocalAuthority");
            return false;
        }
        
        final CredClient cred = new CredClient(credURI);
        Subject opsSubject = createOpsSubject();
        try {
            privateKeyChain = Subject.doAs(opsSubject, new PrivilegedExceptionAction<X509CertificateChain>() {
                public X509CertificateChain run() throws Exception {
                    return cred.getProxyCertificate(subject, PROXY_CERT_DURATION);
                }
            });
        } catch (PrivilegedActionException ex) {
            throw new RuntimeException("CredClient.getProxyCertficate failed", ex.getException());
        }

        if (privateKeyChain == null) {
            throw new AccessControlException("credential service did not return a delegated certificate");
        }

        privateKeyChain.getChain()[0].checkValidity();
        // carefully remove the previous chain
        Iterator iter = subject.getPublicCredentials().iterator();
        while (iter.hasNext()) {
            Object o = iter.next();
            if (o instanceof X509CertificateChain) {
                iter.remove();
            }
        }
        subject.getPublicCredentials().add(privateKeyChain);
        
        return true;
    }
}
