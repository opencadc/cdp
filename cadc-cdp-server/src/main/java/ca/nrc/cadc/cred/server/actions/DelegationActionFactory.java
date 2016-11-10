/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2011.                            (c) 2011.
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

package ca.nrc.cadc.cred.server.actions;

import ca.nrc.cadc.auth.*;

import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import ca.nrc.cadc.cred.server.CertificateDAO;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.profiler.Profiler;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;

/**
 * Class used to construct the appropriate delegation action.
 * 
 */
public class DelegationActionFactory
{
    private static final Logger log = Logger.getLogger(DelegationActionFactory.class);
    
    // The HTTP Servlet request
    private HttpServletRequest request;

    // The set of trusted principals
    private Map<X500Principal, Float> trustedPrincipals;
    
    private String dataSource;
    private String catalog;
    private String schema;

    /**
     * Factory constructor.
     * 
     * @param request
     * @param trustedPrincipals
     * @param dataSource
     * @param catalog
     * @param schema
     */
    public DelegationActionFactory(HttpServletRequest request, Map<X500Principal, Float> trustedPrincipals,
        String dataSource, String catalog, String schema)
    {
        this.request = request;
        if ((trustedPrincipals == null) || trustedPrincipals.isEmpty())
        {
            throw new IllegalArgumentException("Null or empty trusted principals");
        }
        this.trustedPrincipals = trustedPrincipals;
        this.dataSource = dataSource;
        this.catalog = catalog;
        this.schema = schema;
    }

    private CertificateDAO getDAO()
    {
        CertificateDAO.CertificateSchema config = new CertificateDAO.CertificateSchema(dataSource, catalog);
        return new CertificateDAO(config);
    }
    
    /**
     * @return 
     * Return the appropriate delegation action for this request.
     */
    public DelegationAction getDelegationAction()
    {
        Float daysValid = null;
        X500Principal target = null;
        
        // parameter for daysValid (compatibile with the old ProxyCertServlet)
        String daysValidStr = request.getParameter("daysValid");
        if (daysValidStr != null)
        {
            try
            {
                daysValid = new Float(daysValidStr);
                if (daysValid < 0.0)
                    throw new IllegalArgumentException("invalid daysValid param:"
                        + daysValidStr + " expected: number > 0.0");
            }
            catch (NumberFormatException ex)
            {
                throw new IllegalArgumentException("invalid daysValid param:"
                        + daysValidStr + " expected: number > 0.0");
            }
        }
        
        String resource = request.getPathInfo();
        if (resource != null)
        {
            // TODO: switch to the ?idType= pattern instead of hiding it in the path
            
            // not sure why whitespaces are not decode properly
            resource = resource.replace("+", " ");
            if (resource.startsWith("/"))
                resource = resource.substring(1);

            String[] pathElements = resource.split("/");

            if (pathElements.length > 2)
            {
                return new NotFoundAction(null, trustedPrincipals);
            }

            if (pathElements[0].equalsIgnoreCase("dn"))
            {
                log.debug("GetProxyCertByDN: " + pathElements[1]);
                target = new X500Principal(pathElements[1]);
            }
            else if (pathElements[0].equalsIgnoreCase("userid"))
            {
                log.debug("GetProxyCertByUserid: " + pathElements[1]);
                try
                {
                    target = getX500FromUserID(pathElements[1]);
                }
                catch(ResourceNotFoundException ex)
                {
                    return new NotFoundAction(null, trustedPrincipals);
                }
            }
        }
        
        // target could be null
        return new GetProxyCertByDN(target, daysValid,  trustedPrincipals, getDAO());
    }
    
    protected X500Principal getX500FromUserID(final String userid)
        throws ResourceNotFoundException
    {
        Profiler profiler = new Profiler(DelegationActionFactory.class);
        // create subject with specified userid and augment with other identities
        Subject s = AuthenticationUtil.getSubject(new PrincipalExtractor()
        {
            public Set<Principal> getPrincipals()
            {
                Set<Principal> ps = new HashSet<Principal>();
                ps.add(new HttpPrincipal(userid));
                return ps;
            }

            public X509CertificateChain getCertificateChain()
            {
                return null;
            }

            public DelegationToken getDelegationToken()
            {
                return null;
            }

            /**
             * Create and return a SSOCookieCredential from the request
             *
             * @return
             */
            @Override
            public SSOCookieCredential getSSOCookieCredential()
            {
                return null;
            }
        });
        log.debug("augmented: " + s);
        profiler.checkpoint("getUser");
        
        Set<X500Principal> xp = s.getPrincipals(X500Principal.class);
        if (xp.isEmpty())
        {
            throw new ResourceNotFoundException("user not found: " + userid);
        }
        else
        {
            return xp.iterator().next();
        }
    }

    /**
     * Action indicating that a resource could not be found.
     */
    static final class NotFoundAction extends DelegationAction
    {

        public NotFoundAction(X500Principal name,
                Map<X500Principal, Float> trustedPrincipals)
        {
            super(name, Float.MIN_VALUE, trustedPrincipals, null);
        }

        @Override
        public X509CertificateChain getCertificate(X500Principal name)
                throws Exception
        {
            throw new ResourceNotFoundException("not found: " + name.getName());
        }

    }

    /**
     * Action indicating that a request is not currently supported.
     */
    static final class UnsupportedOperationAction extends
            DelegationAction
    {

        public UnsupportedOperationAction(X500Principal name,
                Map<X500Principal, Float> trustedPrincipals)
        {
            super(name, Float.MIN_VALUE, trustedPrincipals, null);
        }

        @Override
        public X509CertificateChain getCertificate(X500Principal name)
                throws Exception
        {
            throw new UnsupportedOperationException();
        }

    }

}
