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

package ca.nrc.cadc.cred.server;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.sql.Types;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SingleColumnRowMapper;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.db.DBUtil;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.vosi.avail.CheckDataSource;
import ca.nrc.cadc.vosi.avail.CheckResource;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import javax.naming.NamingException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Class to persist certificates in a relational database table. This class has 
 * been only tested with Sybase ASE 15 so far.
 * 
 * @author pdowler
 *
 */
public class CertificateDAO
{
    private static final Logger logger = Logger.getLogger(CertificateDAO.class);

    private final CertificateSchema config;

    public static class CertificateSchema
    {
        private final String dataSourceName;
        private final String table = "x509_certificates";

        private final String certTable;
        
        //public CertificateSchema(String dataSourceName, String catalog, String schema)
        public CertificateSchema(String dataSourceName, String catalog)
        {
            this.dataSourceName = dataSourceName;
            //this.certTable = catalog + "." + schema + "." + table;
            this.certTable = catalog + "." + table;
        }
        
        public String getTable()
        {
            return certTable;
        }

        public DataSource getDataSource()
        {
            try
            {
                logger.debug("lookup datasource: " + dataSourceName);
                return DBUtil.getDataSource(dataSourceName);
            }
            catch(NamingException ex)
            {
                throw new RuntimeException("CONFIG: failed to find DataSource " + dataSourceName);
            }
        }
        
    }
    public CertificateDAO(CertificateSchema config)
    {
        this.config = config;
    }
    
    public CheckResource getCheckResource()
    {
        String sql = "select top 1 hash_dn from " + config.getTable();
        return new CheckDataSource(config.getDataSource(), sql);
    }

    public void put(X509CertificateChain chain)
    {
        Profiler profiler = new Profiler(this.getClass());
        String hashKey = chain.getHashKey();
        String canonDn = AuthenticationUtil.canonizeDistinguishedName(chain.getPrincipal().getName());
        Date expDate = chain.getExpiryDate();
        String certChainStr = chain.certificateString();
        byte[] bytesPrivateKey = chain.getPrivateKey().getEncoded();
        //TODO just for testing - padded with zeros
        byte[] testBytesPrivateKey = Arrays.copyOf(bytesPrivateKey, bytesPrivateKey.length+1);
        testBytesPrivateKey[testBytesPrivateKey.length-1]=1;
        String csr = chain.getCsrString();
        
        JdbcTemplate jdbc = new JdbcTemplate(config.getDataSource());
        if (recordExists(hashKey))
        {
            String sql = "update " + config.getTable()
                    + " set canon_dn = ?, exp_date = ?, cert_chain = ?, private_key = ?, csr = ? where hash_dn=?";
            Object[] args = new Object[] { canonDn, expDate, certChainStr, testBytesPrivateKey, csr, hashKey };
            int[] argTypes = new int[] { Types.VARCHAR, Types.TIMESTAMP, Types.VARCHAR, Types.VARBINARY, Types.VARCHAR, Types.VARCHAR };
            jdbc.update(sql, args, argTypes);
        }
        else
        {
            String sql = "insert into " + config.getTable()
                + " (canon_dn, exp_date, cert_chain, private_key, csr, hash_dn) values (?,?,?,?,?,?)";
            Object[] args = new Object[] { canonDn, expDate, certChainStr, testBytesPrivateKey, csr, hashKey };
            int[] argTypes = 
                new int[] { Types.VARCHAR, Types.TIMESTAMP, Types.VARCHAR, Types.VARBINARY, Types.VARCHAR, Types.VARCHAR };

            jdbc.update(sql, args, argTypes);
        }
        profiler.checkpoint("put");
    }

    public X509CertificateChain get(X500Principal principal)
    {
        if (principal == null) return null;
        String canonizedDn = AuthenticationUtil.canonizeDistinguishedName(principal.getName());
        X500Principal p = new X500Principal(canonizedDn);
        String hashKey = Integer.toString(p.hashCode());
        return get(hashKey);
    }

    public X509CertificateChain get(String hashKey)
    {
        Profiler profiler = new Profiler(this.getClass());
        X509CertificateChain x509CertificateChain = null;

        String query = "select canon_dn, exp_date, cert_chain, private_key, csr from " + config.getTable() + " where hash_dn = ? ";

        
        try
        {
            JdbcTemplate jdbc = new JdbcTemplate(config.getDataSource());
            Map<String, Object> map = jdbc.queryForMap(query, new String[] { hashKey });
            String canonDn = (String) map.get("canon_dn");
            Date expDate = (Date) map.get("exp_date");
            String certChainStr = (String) map.get("cert_chain");
            byte[] bytesPrivateKey = (byte[]) map.get("private_key");
            
            // Sybase trims the trailing 0's of a varbinary. To compensate we add 0's to the 
            // privateKey byte array. Extra bytes in the private key array are ignored
            // when the key is built so the added 0's are only used when needed.
            // ad 20/07/2011
            bytesPrivateKey = Arrays.copyOf(bytesPrivateKey, bytesPrivateKey.length+10);
            
            String csrStr = (String) map.get("csr");

            PrivateKey privateKey = SSLUtil.readPrivateKey(bytesPrivateKey);
            X500Principal principal = new X500Principal(canonDn);

            if (certChainStr != null)
            {
                byte[] bytesCertChain = certChainStr.getBytes();
                X509Certificate[] certs = SSLUtil.readCertificateChain(bytesCertChain);

                x509CertificateChain = new X509CertificateChain(Arrays.asList(certs));
            }
            else
            {
                x509CertificateChain = new X509CertificateChain(principal, privateKey, csrStr);
            }
            x509CertificateChain.setCsrString(csrStr);
            x509CertificateChain.setExpiryDate(expDate);
            x509CertificateChain.setHashKey(hashKey);
            x509CertificateChain.setKey(privateKey);
            x509CertificateChain.setPrincipal(principal);
        }
        catch (EmptyResultDataAccessException e)
        {
            // Record not exists.
            return null;
        }
        catch(InvalidKeySpecException ex)
        {
            throw new RuntimeException("BUG: failed to read private key", ex);
        }
        catch(NoSuchAlgorithmException ex)
        {
            throw new RuntimeException("BUG: failed to read private key", ex);
        }
        catch(CertificateException ex)
        {
            throw new RuntimeException("BUG: failed to read certficate chain", ex);
        }
        catch(IOException ex)
        {
            throw new RuntimeException("BUG: failed to read certificate chain", ex);
        }
        profiler.checkpoint("get");
        return x509CertificateChain;
    }

    /* (non-Javadoc)
     * @see ca.nrc.cadc.accesscontrol.dao.CertificateDAO#delete(java.lang.String)
     */
    public void delete(String hashKey)
    {
        Profiler profiler = new Profiler(this.getClass());
        String sql = "delete from " + config.getTable() + " where hash_dn = ? ";
        JdbcTemplate jdbc = new JdbcTemplate(config.getDataSource());
        jdbc.update(sql, new String[] { hashKey });
        profiler.checkpoint("delete");
    }

    private boolean recordExists(String hashKey)
    {
        RowMapper rowMapper = new SingleColumnRowMapper(String.class);
        String query = "select canon_dn from " + config.getTable() + " where hash_dn = ? ";
        JdbcTemplate jdbc = new JdbcTemplate(config.getDataSource());
        List<String> dnList = jdbc.query(query, new String[] { hashKey }, rowMapper);
        return (dnList != null && dnList.size() == 1);
    }

    public List<String> getAllHashKeys()
    {
        Profiler profiler = new Profiler(this.getClass());
        String query = "select hash_dn from " + config.getTable();
        RowMapper rowMapper = new SingleColumnRowMapper(String.class);
        JdbcTemplate jdbc = new JdbcTemplate(config.getDataSource());
        List<String> hashKeyList = jdbc.query(query, rowMapper);
        profiler.checkpoint("getAllHashKeys");
        return hashKeyList;
    }


}
