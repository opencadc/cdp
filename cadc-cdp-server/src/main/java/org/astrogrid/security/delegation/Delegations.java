package org.astrogrid.security.delegation;

import ca.nrc.cadc.auth.X509CertificateChain;
import java.io.IOException;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

/**
 * Abstract class for the persistence layer. Clients that provide their own 
 * persistence layer need to provide an extension of this class as the
 * org.astrogrid.security.delegation.DelegationsImpl. When the client provided
 * extension class is not available in the classpath, a default, in-memory
 * implementation is used.
 */
public abstract class Delegations
{

    static private Delegations instance;

    static public Delegations getInstance()
    {
        if (instance == null)
        {
            // first, try to get a user-provided Delegations
            // implementation class
            try
            {
                Class<?> implClass = Class
                        .forName("org.astrogrid.security.delegation.DelegationsImpl");
                instance = (Delegations) implClass.newInstance();
            }
            catch (ClassNotFoundException ex)
            {
                // use the default one
                instance = new InMemoryDelegations();
            }
            catch (InstantiationException e)
            {
                throw new RuntimeException("Cannon instantiate DelegationImpl", e);
            }
            catch (IllegalAccessException e)
            {
                throw new RuntimeException("Cannon instantiate DelegationImpl", e);
            }
        }
        return instance;
    }

    /**
     * Determines the hash-key corresponding to a principal.
     * 
     * @param principal
     *            The identity to be hashed.
     * @return The hash.
     */
    public String hash(X500Principal principal)
    {
        //return Integer.toString(principal.hashCode());
        return X509CertificateChain.genHashKey(principal);
    }

    /**
     * Initializes a group of credentials for one identity. If there were
     * already credentials for that identity, nothing is changed. If not,
     * a key pair and a CSR are generated and stored; the certificate
     * property is set to null.
     * 
     * @return The hash of the distinguished name.
     */
    public abstract String initializeIdentity(String identity)
            throws GeneralSecurityException;

    /**
     * Initializes a group of credentials for one identity. If there were
     * already credentials for that identity, nothing is changed. If not,
     * a key pair and a CSR are generated and stored; the certificate
     * property is set to null.
     * 
     * @param principal
     *            The distinguished name on which to base the identity.
     * @return The hash key corresponding to the distinguished name.
     */
    public abstract String initializeIdentity(X500Principal principal)
            throws GeneralSecurityException;

    public abstract CertificateSigningRequest getCsr(String hashKey);

    public abstract PrivateKey getPrivateKey(String hashKey);

    public abstract X509Certificate[] getCertificates(String hashKey);

    public abstract void remove(String hashKey);

    /**
     * Reveals whether an identity is known from the delegation records.
     */
    public abstract boolean isKnown(String hashKey);

    /**
     * Stores a certificate for the given identity. Any previous
     * certificate is overwritten. This operation is thread-safe against
     * concurrent reading of the certificate.
     */
    public abstract void setCertificates(String hashKey, X509Certificate[] certificates) throws InvalidKeyException;

    public abstract Object[] getPrincipals();

    public abstract String getName(String hashKey);

    /**
     * Reveals the keys held for an identity.
     * 
     * @param hashKey
     *            The hash of the identity.
     * @return The keys (null if identity not known).
     */
    public abstract KeyPair getKeys(String hashKey);

    /**
     * Reveals whether a certificate is held for this identity.
     * 
     * @param hashKey
     *            The hash key identifying the user.
     */
    public abstract boolean hasCertificate(String hashKey);

    /**
     * Writes a user's certificate to a given stream, in PEM encoding.
     * 
     * @param hashKey
     *            The hash key identifying the user.
     * @param out
     *            The destination for the certificate.
     */
    public abstract void writeCertificate(String hashKey, Writer out)
            throws IOException;
}
