DO
$$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'replica') THEN
      CREATE ROLE replica WITH LOGIN REPLICATION PASSWORD 'replica';
   ELSE
      ALTER ROLE replica WITH LOGIN REPLICATION PASSWORD 'replica';
   END IF;
END
$$;
