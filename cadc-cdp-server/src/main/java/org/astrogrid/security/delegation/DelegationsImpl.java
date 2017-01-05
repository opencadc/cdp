/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÃ‰ES ASTRONOMIQUES  **************
*
*  (c) 2009.                            (c) 2009.
*  Government of Canada                 Gouvernement du Canada
*  National Research Council            Conseil national de recherches
*  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
*  All rights reserved                  Tous droits rÃ©servÃ©s
*                                       
*  NRC disclaims any warranties,        Le CNRC dÃ©nie toute garantie
*  expressed, implied, or               Ã©noncÃ©e, implicite ou lÃ©gale,
*  statutory, of any kind with          de quelque nature que ce
*  respect to the software,             soit, concernant le logiciel,
*  including without limitation         y compris sans restriction
*  any warranty of merchantability      toute garantie de valeur
*  or fitness for a particular          marchande ou de pertinence
*  purpose. NRC shall not be            pour un usage particulier.
*  liable in any event for any          Le CNRC ne pourra en aucun cas
*  damages, whether direct or           Ãªtre tenu responsable de tout
*  indirect, special or general,        dommage, direct ou indirect,
*  consequential or incidental,         particulier ou gÃ©nÃ©ral,
*  arising from the use of the          accessoire ou fortuit, rÃ©sultant
*  software.  Neither the name          de l'utilisation du logiciel. Ni
*  of the National Research             le nom du Conseil National de
*  Council of Canada nor the            Recherches du Canada ni les noms
*  names of its contributors may        de ses  participants ne peuvent
*  be used to endorse or promote        Ãªtre utilisÃ©s pour approuver ou
*  products derived from this           promouvoir les produits dÃ©rivÃ©s
*  software without specific prior      de ce logiciel sans autorisation
*  written permission.                  prÃ©alable et particuliÃ¨re
*                                       par Ã©crit.
*                                       
*  This file is part of the             Ce fichier fait partie du projet
*  OpenCADC project.                    OpenCADC.
*                                       
*  OpenCADC is free software:           OpenCADC est un logiciel libre ;
*  you can redistribute it and/or       vous pouvez le redistribuer ou le
*  modify it under the terms of         modifier suivant les termes de
*  the GNU Affero General Public        la â€œGNU Affero General Public
*  License as published by the          Licenseâ€ telle que publiÃ©e
*  Free Software Foundation,            par la Free Software Foundation
*  either version 3 of the              : soit la version 3 de cette
*  License, or (at your option)         licence, soit (Ã  votre grÃ©)
*  any later version.                   toute version ultÃ©rieure.
*                                       
*  OpenCADC is distributed in the       OpenCADC est distribuÃ©
*  hope that it will be useful,         dans lâ€™espoir quâ€™il vous
*  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
*  without even the implied             GARANTIE : sans mÃªme la garantie
*  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÃ‰
*  or FITNESS FOR A PARTICULAR          ni dâ€™ADÃ‰QUATION Ã€ UN OBJECTIF
*  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
*  General Public License for           GÃ©nÃ©rale Publique GNU Affero
*  more details.                        pour plus de dÃ©tails.
*                                       
*  You should have received             Vous devriez avoir reÃ§u une
*  a copy of the GNU Affero             copie de la Licence GÃ©nÃ©rale
*  General Public License along         Publique GNU Affero avec
*  with OpenCADC.  If not, see          OpenCADC ; si ce nâ€™est
*  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
*                                       <http://www.gnu.org/licenses/>.
*
*  $Revision: 4 $
*
************************************************************************
*/

package org.astrogrid.security.delegation;

import java.io.IOException;
import java.io.Writer;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.CertUtil;
import ca.nrc.cadc.cred.server.CertificateDAO;
import org.apache.log4j.Logger;
import org.astrogrid.security.delegation.InMemoryDelegations.DelegatedIdentity;
//import static DelegationsImpl.DATASOURCE;

/**
 * Implementation of the base Delegations class in the 
 * org.astrogrid.security.delegation package.
 */
public class DelegationsImpl extends Delegations
{
    private static final Logger log = Logger.getLogger(DelegationsImpl.class);
    
    public static final String DATASOURCE = "jdbc/oatscdp";
    public static final String CATALOG = "oatscdp";
    //public static final String SCHEMA = "dbo";
    private CertificateDAO certificateDAO = null;
    private KeyPairGenerator keyPairGenerator;
    
    /**
     * constructor
     *  
     */
    public DelegationsImpl()
    {
        // Add the Bouncy Castle JCE provider. This allows the CSR
        // classes to work. The BC implementation of PKCS#10 depends on
        // the ciphers in the BC provider.
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try
        {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(CertUtil.DEFAULT_KEY_LENGTH);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new RuntimeException("BUG/CONFIG: cannot load RSA key-pair generator", ex);
        }
        
        //CertificateDAO.CertificateSchema config = new CertificateDAO.CertificateSchema(DATASOURCE, CATALOG, SCHEMA);
        
        CertificateDAO.CertificateSchema config = new CertificateDAO.CertificateSchema(DATASOURCE, CATALOG);
        
        certificateDAO = new CertificateDAO(config);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#initializeIdentity(java.lang.String)
     */
    @Override
    public String initializeIdentity(String identity) throws GeneralSecurityException
    {
        try
        {
            String canonizedDn = AuthenticationUtil.canonizeDistinguishedName(identity);
            X500Principal p = new X500Principal(canonizedDn);
            return initializeIdentity(p);
        }
        catch(GeneralSecurityException gex)
        {
            log.debug("initializeIdentity failed", gex);
            throw gex;
        }
        catch(RuntimeException t)
        {
            log.debug("initializeIdentity failed", t);
            throw t;
        }
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#initializeIdentity(javax.security.auth.x500.X500Principal)
     */
    @Override
    public String initializeIdentity(X500Principal principal) throws GeneralSecurityException
    {
        try
        {
            String canonizedDn = AuthenticationUtil.canonizeDistinguishedName(principal.getName());
            X500Principal p = new X500Principal(canonizedDn);
            String hashKey = hash(p);
            KeyPair keyPair = this.keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            log.debug("creating CertificateSigningRequest: " + canonizedDn + "," + keyPair);
            CertificateSigningRequest csr = new CertificateSigningRequest(canonizedDn, keyPair);

            X509CertificateChain chain = new X509CertificateChain(p, privateKey, Util.getCsrString(csr));
           
            certificateDAO.put(chain);
            
            return hashKey;
            
        }
        catch(GeneralSecurityException gex)
        {
            log.debug("initializeIdentity failed", gex);
            throw gex;
        }
        catch(RuntimeException t)
        {
            log.debug("initializeIdentity failed", t);
            throw t;
        }
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getCsr(java.lang.String)
     */
    @Override
    public CertificateSigningRequest getCsr(String hashKey)
    {
        X509CertificateChain x509CertificateChain = certificateDAO.get(hashKey);
        if (x509CertificateChain == null)
        {
            return null;
        }
        String csrString = x509CertificateChain.getCsrString();
        CertificateSigningRequest csr = Util.getCsrFromString(csrString);
        return csr;
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String hashKey)
    {
        X509CertificateChain x509CertificateChain = certificateDAO.get(hashKey);
        if (x509CertificateChain == null)
        {
            return null;
        }
        return x509CertificateChain.getPrivateKey();
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getCertificate(java.lang.String)
     */
    @Override
    public X509Certificate[] getCertificates(String hashKey)
    {
        X509CertificateChain x509CertificateChain = certificateDAO.get(hashKey);
        if (x509CertificateChain == null)
        {
            return null;
        }
        return x509CertificateChain.getChain();
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#remove(java.lang.String)
     */
    @Override
    public void remove(String hashKey)
    {
        certificateDAO.delete(hashKey);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#isKnown(java.lang.String)
     */
    @Override
    public boolean isKnown(String hashKey)
    {
        X509CertificateChain chain = certificateDAO.get(hashKey);
        return (chain != null);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#setCertificate(java.lang.String, java.security.cert.X509Certificate)
     */
    @Override
    public void setCertificates(String hashKey, X509Certificate[] certificates) throws InvalidKeyException
    {
        X509CertificateChain chain = certificateDAO.get(hashKey);
        if (chain != null)
        {
            chain.setChain(certificates);
            certificateDAO.put(chain);
        }
        else
            throw new InvalidKeyException("No identity matches the hash key " + hashKey);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getPrincipals()
     */
    @Override
    public Object[] getPrincipals()
    {
//        List<String> hashKeyList = certificateDAO.getAllHashKeys();
//        return hashKeyList.toArray();
        //TODO AD: this is a workaround to send the hash to the caller when it
        // does a listing.
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        Set<X500Principal> principals = subject
                .getPrincipals(X500Principal.class);
        if (principals.size() == 0)
        {
            throw new AccessControlException(
                    "Delegation failed because the caller is not authenticated.");
        }
        else if (principals.size() > 1)
        {
            throw new AccessControlException(
                    "Delegation failed because caller autheticated with multiple certificates.");
        }
        return new String[] { X509CertificateChain.genHashKey(principals
                .iterator().next()) };
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getName(java.lang.String)
     */
    @Override
    public String getName(String hashKey)
    {
        X509CertificateChain x509CertificateChain = certificateDAO.get(hashKey);
        if (x509CertificateChain == null)
        {
            return null;
        }
        String dn = x509CertificateChain.getPrincipal().getName();
        return dn;
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#getKeys(java.lang.String)
     */
    @Override
    public KeyPair getKeys(String hashKey)
    {
        throw new RuntimeException("getKeys() not implemented in DAO version implementation."); 
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#hasCertificate(java.lang.String)
     */
    @Override
    public boolean hasCertificate(String hashKey)
    {
        X509CertificateChain chain = certificateDAO.get(hashKey);
        return (chain.getChain() != null);
    }

    /* (non-Javadoc)
     * @see org.astrogrid.security.delegation.Delegations#writeCertificate(java.lang.String, java.io.Writer)
     */
    @Override
    public void writeCertificate(String hashKey, Writer out) throws IOException
    {
        PEMWriter pem = new PEMWriter(out);
        X509Certificate[] certs = getCertificates(hashKey);
        if (certs == null)
        {
            throw new IllegalArgumentException(
                    "No certificate corresponding to the haskey: " + hashKey);
        }
        for (X509Certificate cert : certs)
        {
            pem.writeObject(cert);
        }
        pem.flush();
        pem.close();
    }
    
    
    protected class DelegatedIdentity {
      protected final String                    dn;
      protected final KeyPair                   keys;
      protected final CertificateSigningRequest csr;
      protected X509Certificate                 certificate;

      protected DelegatedIdentity(String  dn,
                                  KeyPair keys) throws GeneralSecurityException {
        this.dn          = dn;
        this.keys        = keys;
        this.csr         = new CertificateSigningRequest(dn, keys);
        this.certificate = null;
      }

      protected synchronized X509Certificate getCertificate() {
        return certificate;
      }

      protected synchronized void setCertificate(X509Certificate c) throws InvalidKeyException {
        if (c.getPublicKey().equals(keys.getPublic())) {
          certificate = c;
        }
        else {
          throw new InvalidKeyException("This certificate does not match the cached private-key.");
        }
      }

      protected KeyPair getKeys() {
        return keys;
      }

    }
    
}
