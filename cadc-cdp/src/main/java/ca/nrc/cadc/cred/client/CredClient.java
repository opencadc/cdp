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

package ca.nrc.cadc.cred.client;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.CertUtil;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.Base64;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Set;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

public class CredClient
{
    private static Logger LOGGER = Logger.getLogger(CredClient.class);
    
    private URI serviceID;
    private RegistryClient reg;
    
    public CredClient(URI serviceID)
    {
        if (serviceID == null)
            throw new IllegalArgumentException("invalid serviceID: " + serviceID);
        if (serviceID.getFragment() != null)
            throw new IllegalArgumentException("invalid serviceID (fragment not allowed): " + serviceID);
        this.serviceID = serviceID;
    }

    String getServiceBaseURL() {
        URL u = getRegistryClient().getServiceURL(serviceID, Standards.VOSI_CAPABILITIES, AuthMethod.ANON);
        String ret = u.toExternalForm().replace("/capabilities", "");
        return ret;
    }
    
    /**
     * Get a proxy certificate for the specified user (subject). This operation is
     * currently a custom feature of the cadcCDP-Server implementation that allows
     * authorized callers to generate short-lived proxy certificates.
     * 
     * @param subject the target user
     * @param daysValid the length of time the proxy certificate should be valid for
     * @return 
     * @throws CertificateException 
     * @throws java.io.IOException 
     * @throws ca.nrc.cadc.net.ResourceNotFoundException 
     */
    public X509CertificateChain getProxyCertificate(Subject subject, double daysValid)
            throws AccessControlException, CertificateException, IOException, ResourceNotFoundException {
        
        Set<Principal> principals = subject.getPrincipals();
        // get the first available X500, HTTP Principal
        X500Principal x500Principal = null;
        HttpPrincipal httpPrincipal = null;
        for (Principal principal : principals)
        {
            if (principal instanceof X500Principal
                    && x500Principal == null)
            {
                x500Principal = (X500Principal) principal;
            }
            else if (principal instanceof HttpPrincipal
                    && httpPrincipal == null)
            {
                httpPrincipal = (HttpPrincipal) principal;
            }
        }

        StringBuilder path = new StringBuilder();
        
        // If an X500 Principal exists, get the certificate based on the
        // DN. Otherwise, if an HTTP Principal exists, get the 
        // certificate based on the userid.
        
        try
        {
            if (x500Principal != null)
            {
                String dn = AuthenticationUtil.canonizeDistinguishedName(x500Principal.getName());
                path.append("/dn/").append(NetUtil.encode(dn));
            }
            else if (httpPrincipal != null)
            {
                path.append("/userid/").append(httpPrincipal.getName());
            }
            else
                throw new UnsupportedOperationException("current subject lacks supported principal type");
            
            if (daysValid > 0)
            {
                path.append("?daysValid=").append(String.valueOf(daysValid));
            }

            LOGGER.debug("serviceID: " + this.serviceID);
            URL credUrl = getRegistryClient().getServiceURL(this.serviceID, Standards.CRED_PROXY_10, AuthMethod.CERT);
            if (credUrl == null) {
                throw new RuntimeException("lookup failed: " + serviceID + " + " + Standards.CRED_PROXY_10 + " + " + AuthMethod.CERT);
            }
            URL url = new URL(credUrl.toExternalForm() + path.toString());
            LOGGER.debug("getCertficate: " + url.toString());
            return downloadCertificate(url);
        }
        finally { }
    }

    /**
     * Delegate current subject credentials to the service (IVOA CDP-1.0).
     * 
     * @param days
     * @throws MalformedURLException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws CertificateEncodingException
     * @throws CertificateParsingException
     * @throws CertificateExpiredException
     * @throws CertificateNotYetValidException 
     * @throws ca.nrc.cadc.net.ResourceNotFoundException 
     */
    public void delegate(double days)
            throws MalformedURLException, IOException,
            InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateEncodingException, CertificateParsingException,
            CertificateExpiredException, CertificateNotYetValidException, ResourceNotFoundException
    {
        delegate(null, days);
    }
    
    /**
     * Custom delegation method that allows the caller to have a different DN from
     * the created certificate DN. This feature allows the caller/signer to use the
     * CDP service as a certificate authority (see: cadc-cert-gen).
     * 
     * @param userDN target DN to create; null for self-delegation
     * @param days
     * @throws MalformedURLException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws CertificateEncodingException
     * @throws CertificateParsingException
     * @throws CertificateExpiredException
     * @throws CertificateNotYetValidException 
     * @throws ca.nrc.cadc.net.ResourceNotFoundException 
     */
    public void delegate(X500Principal userDN, double days)
            throws MalformedURLException, IOException,
            InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateEncodingException, CertificateParsingException,
            CertificateExpiredException, CertificateNotYetValidException, ResourceNotFoundException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        // user does not have the group created. Through a POST.
        // the server generates one and returns it to the user
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(),
                    "UTF-8"));
        }

        URL credUrl = getRegistryClient()
            .getServiceURL(this.serviceID, Standards.CRED_DELEGATE_10, AuthMethod.CERT);
        URL resourceURL = new URL(credUrl.toExternalForm() + "/" + resourcePath.toString());

        LOGGER.debug("delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("POST");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("create step in delegate(), response code: "
                + responseCode);
        LOGGER.debug("create step in delegate(), response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_CREATED:
                String location = connection.getHeaderField("Location");
                int sec = (int) days * 24 * 60 * 60; // seconds
                String csr = getEncodedCSR(location, userDN);
                PKCS10CertificationRequest req = readCSR(csr.getBytes());
                X509Certificate cert = generateV3Certificate(req, sec);
                X509Certificate[] chain = createProxyCertChain(cert);
                putSignedCert(location, chain, userDN);

                break;
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new AccessControlException(responseMessage);
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                throw new ResourceNotFoundException(responseMessage);
            case HttpURLConnection.HTTP_OK:
                // break intentionally left out
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Creates the resource (private key, public key, CSR) for userDN. This is the
     * first step of the sequence used by the delegate method.
     * 
     * @param userDN
     * @return URL to the newly create resource
     * @throws IOException
     * @throws ca.nrc.cadc.net.ResourceNotFoundException
     */
    public String createResoure(X500Principal userDN) throws IOException, ResourceNotFoundException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        // user does not have the group created. Through a POST.
        // the server generates one and returns it to the user
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(),
                    "UTF-8"));
        }

        URL credUrl = getRegistryClient()
            .getServiceURL(this.serviceID, Standards.CRED_DELEGATE_10, AuthMethod.CERT);
        URL resourceURL = new URL(credUrl.toExternalForm() + "/" + resourcePath.toString());

        LOGGER.debug("delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("POST");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("create step in delegate(), response code: "
                + responseCode);
        LOGGER.debug("create step in delegate(), response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_CREATED:
                return connection.getHeaderField("Location");
            case HttpURLConnection.HTTP_OK:
                // break intentionally left out
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                throw new ResourceNotFoundException(responseMessage);
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_FORBIDDEN:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Delete the resource (private key, public key, CSR) for userDN.
     * 
     * @param userDN
     * @throws IOException
     * @throws CertificateException
     * @throws ca.nrc.cadc.net.ResourceNotFoundException
     */
    public void deleteResource(X500Principal userDN) throws IOException,
            CertificateException, ResourceNotFoundException
    {
        String location = getLocation(userDN);
        final StringBuilder resourcePath = new StringBuilder(64);
        resourcePath.append(location);
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(),
                    "UTF-8"));
        }

        final URL resourceURL = new URL(resourcePath.toString());

        LOGGER.debug("delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("DELETE");
        connection.setDoInput(true);
        connection.setDoOutput(false);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("delete step in delegate(), response code: "
                + responseCode);
        LOGGER.debug("delete step in delegate(), response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_NO_CONTENT:
                return;
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                throw new ResourceNotFoundException(responseMessage);
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_FORBIDDEN:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

     /**
     * Accesses the Certificate Signing Request associated with a user
     * 
     * @param userDN
     *            The DN of the user that owns the CSR.
     * @return CSR
     * @throws IOException
     * @throws java.security.InvalidKeyException
     * @throws java.security.cert.CertificateEncodingException
     * @throws java.security.cert.CertificateParsingException
     * @throws java.security.cert.CertificateExpiredException
     * @throws java.security.cert.CertificateNotYetValidException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.SignatureException
     * @throws ca.nrc.cadc.net.ResourceNotFoundException
     * 
     */
    public String getEncodedCSR(X500Principal userDN) throws IOException,
            InvalidKeyException, CertificateEncodingException,
            CertificateParsingException, CertificateExpiredException,
            CertificateNotYetValidException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException, ResourceNotFoundException
    {
        String location = getLocation(userDN);
        if (location == null)
        {
            throw new IllegalArgumentException(
                    "No certificate found for " + userDN);
        }
        return getEncodedCSR(location, userDN);
    }

    private String getEncodedCSR(String location, X500Principal userDN)
            throws IOException, InvalidKeyException,
            NoSuchProviderException, NoSuchAlgorithmException,
            SignatureException, CertificateEncodingException,
            CertificateParsingException, CertificateExpiredException,
            CertificateNotYetValidException, ResourceNotFoundException
    {
        final URL resourceURL = new URL(location + "/CSR");
        LOGGER.debug("get CSR step in delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("GET");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("get CSR step in delegate(), response code: "
                + responseCode);
        LOGGER.debug("get CSR step in delegate(), response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_OK:
                try
                {
                    byte[] csr = null;
                    InputStream in = connection.getInputStream();
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    int bytesRead;
                    byte[] buffer = new byte[1024];
                    while ((bytesRead = in.read(buffer, 0, buffer.length)) != -1)
                    {
                        out.write(buffer, 0, bytesRead);
                    }
                    out.flush();
                    csr = out.toByteArray();
                    in.close();
                    LOGGER.debug("Downloaded CSR of size: " + csr.length);
                    return new String(csr);

                }
                catch (UnsupportedEncodingException e)
                {
                    throw new RuntimeException(
                            "UTF-8 encoding not supported");
                }
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                throw new ResourceNotFoundException(responseMessage);
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_FORBIDDEN:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

   
    /**
     * Accesses the certificate associated with a user/location.
     * 
     * @param userDN
     * @return X509Certificate from the CDP URL of the resource that owns
     *         the certificate
     * @throws IOException
     * @throws java.security.InvalidKeyException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.SignatureException
     * @throws java.security.cert.CertificateEncodingException
     * @throws java.security.cert.CertificateParsingException
     * @throws ca.nrc.cadc.net.ResourceNotFoundException
     */
    public X509Certificate[] getCertificate(X500Principal userDN)
            throws IOException, InvalidKeyException,
            NoSuchProviderException, NoSuchAlgorithmException,
            SignatureException, CertificateEncodingException,
            CertificateParsingException, CertificateException, ResourceNotFoundException
    {
        String location = getLocation(userDN);
        final URL resourceURL = new URL(location + "/certificate");
        LOGGER.debug("get certificate, URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("GET");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("get certificate, response code: " + responseCode);
        LOGGER.debug("get certificate, response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_OK:
                try
                {
                    InputStream in = connection.getInputStream();
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    int bytesRead;
                    byte[] buffer = new byte[1024];
                    while ((bytesRead = in.read(buffer, 0, buffer.length)) != -1)
                    {
                        out.write(buffer, 0, bytesRead);
                    }
                    out.flush();
                    byte[] certBuf = out.toByteArray();
                    in.close();

                    X509Certificate[] certs = SSLUtil
                            .readCertificateChain(SSLUtil
                                    .getCertificates(certBuf));
                    return certs;

                }
                catch (UnsupportedEncodingException e)
                {
                    throw new RuntimeException(
                            "UTF-8 encoding not supported");
                }
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                throw new ResourceNotFoundException(responseMessage);
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Gets the URL corresponding to the resource in CDP
     * 
     * @param userDN
     * @return hash code used to access subject's resource in CDP
     * @throws IOException
     * @throws java.security.cert.CertificateException
     * @throws ca.nrc.cadc.net.ResourceNotFoundException
     */
    public String getLocation(X500Principal userDN) throws IOException,
            CertificateException, ResourceNotFoundException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        // user does not have the group created. Through a POST.
        // the server generates one and returns it to the user
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(),
                    "UTF-8"));
        }

        URL credUrl = getRegistryClient()
            .getServiceURL(this.serviceID, Standards.CRED_DELEGATE_10, AuthMethod.CERT);
        URL resourceURL = new URL(credUrl.toExternalForm() + "/" + resourcePath.toString());
        
        LOGGER.debug("get hash, URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("GET");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("get hash, response code: " + responseCode);
        LOGGER.debug("get hash, response message: " + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_OK:
                try
                {
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(connection
                                    .getInputStream()));
                    String hash = reader.readLine();
                    if (reader.readLine() != null)
                    {
                        throw new CertificateException(
                                "Only one hash expected");
                    }
                    String hashPath = "/" + hash;
                    URL u = new URL(credUrl.toExternalForm() + "/" + hashPath);
                    return u.toExternalForm();
                }
                catch (UnsupportedEncodingException e)
                {
                    throw new RuntimeException(
                            "UTF-8 encoding not supported");
                }
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                throw new ResourceNotFoundException(responseMessage);
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Puts a signed certificate associated with a user/location.
     * 
     * @param chain
     * @throws IOException
     * @throws java.security.InvalidKeyException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.SignatureException
     * @throws CertificateException
     * @throws ca.nrc.cadc.net.ResourceNotFoundException
     */
    public void putSignedCert(X509Certificate[] chain) throws IOException,
            InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException, ResourceNotFoundException
    {
        X500Principal delegatedUser = chain[0].getSubjectX500Principal();
        String location = getLocation(delegatedUser);
        putSignedCert(location, chain, delegatedUser);
    }
    
    // append certficate chain with the specified cert to make a valid proxy cert
    private X509Certificate[] createProxyCertChain(X509Certificate cert)
    {
        AccessControlContext ac = AccessController.getContext();
        Subject subject = Subject.getSubject(ac);
        if (subject != null)
        {
            Set<X509CertificateChain> cc = subject.getPublicCredentials(X509CertificateChain.class);
            if (cc.size() > 0)
            {
               X509CertificateChain xcc = cc.iterator().next();
               X509Certificate[] chain = xcc.getChain();
               X509Certificate[] ret = new X509Certificate[chain.length + 1];
               ret[0] = cert;
               for (int i=0; i<chain.length; i++)
               {
                   ret[i+1] = chain[i];
               }
               return ret;
            }
        }
        throw new IllegalStateException("current Subject does not contain a certficate chain");
        
    }

    /**
     * Puts a signed certificate associated with a user/location
     * 
     * @param location
     *            URL of the resource that owns the certificate
     * @param certs
     *            Signed certificate to put.
     * @throws IOException
     */
    private void putSignedCert(String location, X509Certificate[] certs,
            X500Principal userDN) 
            throws IOException,
            InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateEncodingException, CertificateParsingException, ResourceNotFoundException
    {
        LOGGER.debug("putSignedCert: " + userDN + " chain length: " + certs.length);
        
        final StringBuilder resourcePath = new StringBuilder(64);
        // user does not have the group created. Through a POST.
        // the server generates one and returns it to the user
        resourcePath.append(location);
        resourcePath.append("/certificate");
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(), "UTF-8"));
        }

        final URL resourceURL = new URL(resourcePath.toString());
        LOGGER.debug("put certificate step in delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("PUT");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);

        OutputStream os = connection.getOutputStream();
        PEMWriter writer = new PEMWriter(new OutputStreamWriter(os));
        for (X509Certificate c : certs)
        {
            writer.writeObject(c);
        }

        writer.flush();
        writer.close();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER
                .debug("put certificate step in delegate(), response code: "
                        + responseCode);
        LOGGER
                .debug("put certificate step in delegate(), response message: "
                        + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_OK:
                LOGGER.debug("Certificate uploaded");
                break;

            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                throw new ResourceNotFoundException(responseMessage);
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Open a HttpsURLConnection with a SocketFactory created based on
     * user credentials.
     * 
     * @param url
     * @return UTLConnection returns an open https connection to URL
     * @throws IOException
     */
    protected HttpsURLConnection openConnection(final URL url)
            throws IOException
    {
        if (!url.getProtocol().equals("https"))
        {
            throw new IllegalArgumentException("Wrong protocol: "
                    + url.getProtocol() + ". CDP works on https only");
        }
        AccessControlContext ac = AccessController.getContext();
        Subject subject = Subject.getSubject(ac);
        SSLSocketFactory sf = SSLUtil.getSocketFactory(subject);
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setSSLSocketFactory(sf);
        return con;
    }

    public X509Certificate generateV3Certificate(
            PKCS10CertificationRequest csr, int lifetime)
            throws InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateEncodingException, CertificateParsingException,
            CertificateExpiredException, CertificateNotYetValidException
    {

        AccessControlContext ac = AccessController.getContext();
        Subject subject = Subject.getSubject(ac);
        X509CertificateChain chain = null;
        if (subject != null)
        {
            Set<X509CertificateChain> certs = subject
                    .getPublicCredentials(X509CertificateChain.class);
            if (certs.size() > 0)
                chain = certs.iterator().next();
        }
        if (chain == null)
        {
            throw new AccessControlException("Subject not authorized");
        }

        return CertUtil.generateCertificate(csr, lifetime, chain);
    }

    /**
     * Parses a byte array and constructs the corresponding
     * PKCS10CertificationRequest
     * 
     * @param code
     *            bytes containing the CSR
     * @return PKCS10CertificationRequest
     * @throws IOException
     */
    public static PKCS10CertificationRequest readCSR(byte[] code)
            throws IOException
    {
        byte[] crt = getCSR(code);
        return new PKCS10CertificationRequest(crt);
    }

    protected RegistryClient getRegistryClient()
    {
        if (reg == null) {
            this.reg = new RegistryClient();
        }
        return reg;
    }

    static byte[] getCSR(byte[] certBuf) throws IOException
    {
        BufferedReader rdr = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(certBuf)));
        String line = rdr.readLine();
        StringBuilder base64 = new StringBuilder();
        while (line != null)
        {
            if (line.startsWith("-----BEGIN CERTIFICATE REQUEST-"))
            {
                LOGGER.debug(line);
                line = rdr.readLine();
                while (line != null
                        && !line
                                .startsWith("-----END CERTIFICATE REQUEST-"))
                {
                    LOGGER.debug(line + " (" + line.length() + ")");
                    base64.append(line.trim());
                    line = rdr.readLine();
                }
                LOGGER.debug(line);
                line = null; // break from outer loop
            }
            else
                line = rdr.readLine();
        }
        rdr.close();
        String encoded = base64.toString();
        LOGGER.debug("CERTIFICATE REQUEST: " + encoded);
        // now: base64 -> byte[]
        byte[] ret = Base64.decode(encoded);
        LOGGER.debug("RSA private key: " + ret.length + " bytes");

        return ret;
    }
    
    /**
     * Accesses the Certificate from the specified location.
     * 
     * @param location
     *            URL of the resource for obtaining the certificate.
     * @throws IOException
     */
    private X509CertificateChain downloadCertificate(URL location)
        throws AccessControlException, IOException, ResourceNotFoundException
    {
        Profiler profiler = new Profiler(this.getClass());
        
        byte[] certificate = null;
        try
        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            HttpGet get = new HttpGet(location, bos);
            
            get.run();
            if ( get.getThrowable() != null)
            {
                if (get.getThrowable() instanceof IOException)
                    throw (IOException) get.getThrowable();
                
                if (get.getThrowable() instanceof AccessControlException)
                    throw (AccessControlException) get.getThrowable();
                
                if (get.getThrowable() instanceof FileNotFoundException)
                    throw new ResourceNotFoundException(get.getThrowable().getMessage(), get.getThrowable());
                
                throw new RuntimeException("unexpected failure download certificate", get.getThrowable());
            }
            
            certificate = bos.toByteArray();
            LOGGER.debug("Downloaded Certificate of size: " + certificate.length);
        }
        finally
        {
            profiler.checkpoint("downloadCertificate");
        }

        if (certificate != null && certificate.length > 0)
        {
            try
            {
                return SSLUtil.readPemCertificateAndKey(certificate);
            }
            catch (GeneralSecurityException e)
            {
                LOGGER.warn(e);
                throw new IllegalStateException("Could not parse the certificate", e);
            }
            finally
            {
                profiler.checkpoint("parseCertificate");
            }
        }
        
        throw new RuntimeException("No content in certificate");
    }
}
