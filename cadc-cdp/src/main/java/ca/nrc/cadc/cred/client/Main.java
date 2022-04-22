/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2015.                            (c) 2015.
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
import ca.nrc.cadc.auth.CertCmdArgUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.CertUtil;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.ArgumentMap;
import ca.nrc.cadc.util.Log4jInit;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

public class Main implements PrivilegedAction<Boolean>
{
    private static Logger logger = Logger.getLogger(Main.class);

    public static final String ARG_HELP = "help";
    public static final String ARG_VERBOSE = "verbose";
    public static final String ARG_DEBUG = "debug";
    public static final String ARG_H = "h";
    public static final String ARG_V = "v";
    public static final String ARG_D = "d";
    public static final String ARG_VIEW_CMD = "view";
    public static final String ARG_DELEGATE_CMD = "delegate";
    public static final String ARG_VALID_DAYS = "daysValid";
    public static final String ARG_RESOUIRCE_ID = "resourceID";
    
    public static final String ARG_GET_PROXY = "get";
    public static final String ARG_USERID = "userid";
    public static final String ARG_USERDN = "userdn";
    public static final String ARG_OUT = "out";



    // authenticated subject
    private static Subject subject;

    private String baseURL;
    private RegistryClient registryClient = new RegistryClient();
    private CredClient client;

    private Double daysValid;
    private String userID;
    private String userDN;
    private PrintWriter outPEM;

    private static final int INIT_STATUS = 1; // exit code for
    // initialisation failure
    private static final int NET_STATUS = 2; // exit code for

    // client-server failures

    // Operations on Cred client
    public enum Operation {
        DELEGATE, VIEW, GET
    };
    
    private Operation operation; // current operation on Cred client

    /**
     * Main class for accessing CDP
     * 
     * @param args
     */
    public static void main(String[] args)
    {
        ArgumentMap argMap = new ArgumentMap(args);

        if (argMap.isSet(ARG_HELP) || argMap.isSet(ARG_H))
        {
            usage();
            System.exit(0);
        }

        // Set debug mode
        if (argMap.isSet(ARG_DEBUG) || argMap.isSet(ARG_D))
        {
            Log4jInit.setLevel("ca.nrc.cadc.cred", Level.DEBUG);
        }
        else if (argMap.isSet(ARG_VERBOSE) || argMap.isSet(ARG_V))
        {
            Log4jInit.setLevel("ca.nrc.cadc.cred", Level.INFO);
        }
        else
            Log4jInit.setLevel("ca", Level.WARN);

        Main command = new Main();
        
        try
        {
            command.validateCommand(argMap);
        }
        catch (IllegalArgumentException ex)
        {
            msg("illegal argument(s): " + ex.getMessage());
            msg("");
            usage();
            System.exit(INIT_STATUS);
        }

        try
        {
            command.init(argMap);
            Subject.doAs(subject, command);
        }
        catch (Throwable t)
        {
            logger.error("unexpected failure", t);
            System.exit(NET_STATUS);
        }
        System.exit(0);

    }

    /**
     * Runs the task in Subject's context. Needed by the PrivilegedAction
     * interface
     * 
     * @return true if successfull, false otherwise
     */
    public Boolean run()
    {
        logger.info("run - START");
        if (this.operation.equals(Operation.DELEGATE))
        {
            doDelegate();
        }
        else if (this.operation.equals(Operation.VIEW))
        {
            doView();
        }
        else if (this.operation.equals(Operation.GET))
        {
            doGet();
        }
        logger.info("run - DONE");
        return new Boolean(true);
    }

    /**
     * Executes delegate command
     */
    private void doDelegate()
    {
        try
        {
            client.delegate(daysValid);
            msg("Certificate updated");
        }
        catch (Exception e)
        {
            logger.error("failed to delegate", e);
            System.exit(NET_STATUS);
        }

    }

    /**
     * Executes view command
     */
    private void doView()
    {
        try
        {
            X509Certificate[] certs = client.getCertificate(null);
            certs[0].checkValidity();
            msg("Found valid certificate");
            msg("Certificate Subject DN: "
                    + certs[0].getSubjectX500Principal().getName());
            msg("Certificate Expiry Date: " + certs[0].getNotAfter());
            msg("Certificate Details: " + certs[0].toString());
        }
        catch (Exception e)
        {
            logger.error("failed to delegate", e);
            System.exit(NET_STATUS);
        }

    }
    
    private void doGet()
    {
        try
        {
            Set<Principal> ps = new HashSet<Principal>();
            if (userID != null)
                ps.add(new HttpPrincipal(userID));
            else // userDN
                ps.add(new X500Principal(userDN));
            Subject target = new Subject(true, ps, new HashSet<Object>(), new HashSet<Object>());
                    
            double dur = 0.0;
            if (daysValid != null)
                dur = daysValid;
            
            X509CertificateChain chain = client.getProxyCertificate(target, dur);
            CertUtil.writePEMCertificateAndKey(chain, outPEM);
        }
        catch(Exception e)
        {
            logger.error("failed to get", e);
            System.exit(NET_STATUS);
        }
    }

    /**
     * Validates the command line operations
     * 
     * @param argMap
     */
    private void validateCommand(ArgumentMap argMap)
            throws IllegalArgumentException
    {
        String validDaysStr = argMap.getValue(ARG_VALID_DAYS);
        if (validDaysStr != null)
        {
            boolean valid = true;
            try
            {
                daysValid = new Double(validDaysStr);
                if (daysValid <= 0.0)
                {
                    valid = false;
                }
            }
            catch (NumberFormatException ex)
            {
                valid = false;
            }
            if (valid == false)
            {
                logger.error(ARG_VALID_DAYS + " must be a positive double value");
                usage();
                System.exit(INIT_STATUS);
            }
        }
        logger.info("daysValid: " + daysValid);
            
        int numOp = 0;
        if (argMap.isSet(ARG_VIEW_CMD))
        {
            operation = Operation.VIEW;
            numOp++;
        }
        if (argMap.isSet(ARG_DELEGATE_CMD))
        {
            operation = Operation.DELEGATE;
            numOp++;
            
        }
        if (argMap.isSet(ARG_GET_PROXY))
        {
            numOp++;
            operation = Operation.GET;
            this.userID = argMap.getValue(ARG_USERID);
            this.userDN = argMap.getValue(ARG_USERDN);
            if ( (userID == null && userDN == null) || (userID != null && userDN != null) )
            {
                logger.error("one of: " + ARG_USERID + " or " + ARG_USERDN + " must be set");
                usage();
                System.exit(INIT_STATUS);
            }
            String out = argMap.getValue(ARG_OUT);
            if (out != null)
            {
                try
                {
                    this.outPEM = new PrintWriter(new FileWriter(new File(out)));
                }
                catch(IOException ex)
                {
                    logger.error("failed to open " + out + ": " + ex);
                    usage();
                    System.exit(INIT_STATUS);
                }
            }
            else
                this.outPEM = new PrintWriter(System.out);
            
        }
        if (numOp != 1)
        {
            logger.error("Must specify one operation");
            usage();
            System.exit(INIT_STATUS);
        }
    }

    /**
     * Initializes of the base URL for the service
     * 
     * @param argMap
     */
    private void init(ArgumentMap argMap)
    {
        try
        {
            subject = CertCmdArgUtil.initSubject(argMap);
        }
        catch (Exception ex)
        {
            logger.error("failed to initialise SSL from certificates: " + ex.getMessage());
            logger.debug("failed to initialise SSL from certificates: ", ex);
            if (ex instanceof IllegalArgumentException)
            {
                usage();
            }
            System.exit(INIT_STATUS);
        }
        
        String rid = argMap.getValue(ARG_RESOUIRCE_ID);
        if (rid == null)
        {
            usage();
            logger.error("missing required --resourceID");
            System.exit(INIT_STATUS);
        }
        try
        {
            URI resourceID = new URI(rid);
            this.client = new CredClient(resourceID);
            logger.info("created: " + client.getClass().getSimpleName() + " for " + resourceID);
            logger.info("found service: " + client.getServiceBaseURL());
        }
        catch(URISyntaxException ex)
        {
            logger.error("malformed resourceID: " + rid);
            System.exit(INIT_STATUS);
        }
        catch (Exception e)
        {
            logger.error("reason: " + e.getMessage());
            logger.debug("reason", e);
            System.exit(INIT_STATUS);
        }
    }

    /**
     * Formats the usage message.
     */
    public static void usage()
    {
        String[] um = {
                "Usage: cadc-cdp [-v|--verbose|-d|--debug] --resourceID=<CDP service to use> <op> ...",
                CertCmdArgUtil.getCertArgUsage(),
                "",
                "Help: cadc-cdp <-h|--help>",
                "",
                "  --resourceID specifies the CDP service to use (e.g. ivo://cadc.nrc.ca/cred)",
                "",
                "  <op> is one of:    ",
                "  --delegate [--daysValid=<days>]",
                "          create new proxy certificate on the server",
                "  --get --userid=<username> [--out=<file>] [--daysValid=<days>] ",
                "  --get --userdn=<user distinguished name> [--out=<file>] [--daysValid=<days>] ",
                "          get a new (shorter) proxy certificate from the server;",
                "  --view",
                "          view the currently delegated proxy certificate",
        };

        for (String line : um)
            msg(line);

    }

    // encapsulate all messages to console here
    private static void msg(String s)
    {
        System.out.println(s);
    }

}
