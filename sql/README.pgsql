To create the database and grant default permission to pmacctd you have to execute
the two scripts below, in the same order; which user has to execute them and how to
autenticate with the PostgreSQL server depends upon your current configuration.
Keep in mind that both scripts need postgres superuser permissions to execute commands 
successfully:

shell> cp -p *.pgsql /tmp
shell> su - postgres

To create v1 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v1.pgsql

To create v2 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v2.pgsql

Two tables will be created in the 'pmacct' DB. 'acct' (or 'acct_v2' if using v2) table is
the default table where data will be written when in 'frontend' mode (see 'sql_data'
option in CONFIG-KEYS text file; default value is 'frontend'); 'acct_back' (or 'acct_back_v2'
if using v2 tables) is the default table where data will be written when in 'backend'
mode.

A pair of brief explanations: 

- To understand difference between v1 and v2 tables:
  - Do you need agent ID for distributed accounting ? Then you have to use v2.
  - Do you need VLAN traffic accounting ? Then you have to use v2.
  - If all of the above point sound useless, then use v1.

- What is the difference between 'frontend' and 'backend' modes ? What is the 'proto' table ?
'frontend data are final, human readable strings; backend data are integers, IP addresses
represented in network byte order, etc.'. An auxiliar 'proto' table will be created and
contains names of protocols that in 'acct' table are represented as numbers. Joins are
expensive, 'proto' table has been created *only* for your reference. 

NOTE: if you are using 'backend' mode, of course you have the ability to translate data
in a human readable form; PostgreSQL's internal ABSTIME() function is your friend when
handling timestamps in unix format (since epoch); the following stored procedure is a
sample of what you could need to translate IP addresses from integers in network byte
order into strings:

CREATE FUNCTION pm_inet_ntoa(int8) RETURNS CHAR AS '
DECLARE
    t CHAR(15);
BEGIN
    t = ($1 & 255::int8)        || ''.'' ||
        (($1>>8)  & 255::int8)  || ''.'' ||
        (($1>>16) & 255::int8)  || ''.'' ||
        (($1>>24) & 255::int8);
    RETURN t;
END;
' LANGUAGE 'plpgsql';

To create such a function you will need PL/pgSQL language handlers; they have to be created
with the following declarations:

CREATE FUNCTION plpgsql_call_handler() RETURNS OPAQUE AS 'plpgsql.so' LANGUAGE 'C';
CREATE TRUSTED PROCEDURAL LANGUAGE 'plpgsql' HANDLER plpgsql_call_handler LANCOMPILER 'PL/pgSQL';


Moreover; do you like automagical stuff ? Understanding a priori that you will get great 
delays when facing with really large tables, you could also implement a view as a filter
to your "acct_back" table, in the following way:

CREATE VIEW data AS
  SELECT mac_src,
         mac_dst,
         pm_inet_ntoa(ip_src) AS ip_src,
         pm_inet_ntoa(ip_dst) AS ip_dst,
         port_src,
         port_dst,
         ip_proto,
         packets,
         bytes,
         ABSTIME(stamp_inserted)::Timestamp::Timestamp without time zone AS stamp_inserted,
         ABSTIME(stamp_updated)::Timestamp::Timestamp without time zone AS stamp_updated
  FROM acct_data; 



