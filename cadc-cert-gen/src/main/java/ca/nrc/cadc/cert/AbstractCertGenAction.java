/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2015.                            (c) 2015.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author adriand
 *
 * @version $Revision: $
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.cert;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.PrivilegedAction;
import java.security.Security;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ca.nrc.cadc.util.ArgumentMap;
import ca.nrc.cadc.util.StringUtil;

import javax.security.auth.x500.X500Principal;



public abstract class AbstractCertGenAction implements PrivilegedAction<Object>
{
    private static Logger LOGGER = Logger.getLogger(AbstractCertGenAction.class);

    //public static final URI CRED_SERVICE_ID = URI.create("ivo://cadc.nrc.ca/cred");
    public static URI CRED_SERVICE_ID;
    
    protected int expiring;
    protected String userid;

    public AbstractCertGenAction() {
        
        LocalAuthority localAuthority = new LocalAuthority();       
        CRED_SERVICE_ID = localAuthority.getServiceURI(Standards.CRED_DELEGATE_10.toString());
           
    }
    
    public boolean init(final ArgumentMap argMap) throws IOException
    {
        LocalAuthority localAuthority = new LocalAuthority();       
        CRED_SERVICE_ID = localAuthority.getServiceURI(Standards.CRED_DELEGATE_10.toString());

        String expiringString = argMap.getValue(Main.ARG_EXPIRING);
        String userIDString = argMap.getValue(Main.ARG_USERID);

        if (expiringString == null && userIDString == null)
        {
            LOGGER.error("One of " + Main.ARG_EXPIRING + " or " +
                Main.ARG_USERID + " must be provided.");
            return false;
        }

        if (expiringString != null && userIDString != null)
        {
            LOGGER.error("Only one of " + Main.ARG_EXPIRING + " or " +
                Main.ARG_USERID + " must be provided.");
            return false;
        }

        if (expiringString != null)
        {
            expiring = parseExpire(argMap);
        }
        else
        {
            userid = userIDString;
        }

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        return true;
    }

    abstract protected X500Principal[] getExpiring(int expire);
    
    abstract protected X500Principal getCertificateDN(HttpPrincipal userId);
    
    private int parseExpire(ArgumentMap argMap)
    {
        int expire = 0;
        String expireStr = argMap.getValue(Main.ARG_EXPIRING);
        if (StringUtil.hasText(expireStr))
        {
            try
            {
                expire = Integer.parseInt(expireStr);
            }
            catch (NumberFormatException e)
            {
                LOGGER.debug(Main.ARG_EXPIRING + " must be an integer");
                LOGGER.debug("Using the default value instead");
            }
        }
        if (expire == 0)
            expire = Main.DEFAULT_EXPIRE;
        return expire;
    }

    @Override
    public String run()
    {
        try
        {
            runCommand();
            return null;
        }
        catch (Exception e)
        {
            LOGGER.debug("run - ERROR \n" + e.getMessage());
            throw new RuntimeException("execution error", e);
        }
    }

    protected void msg(String msg)
    {
        Main.msg(msg);
    }

    protected abstract void runCommand() throws Exception;

}
