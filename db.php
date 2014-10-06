<?php

/**
 * Standard DB Connector class that wraps PDO functions.
 *
 * Init with:
 *  DB::instance([
 *          'host' => 'localhost', // optional - will default to localhost
 *          'port' => 3306,        // optional - will default to 3306
 *          'user' => '<<< DB USER >>>',
 *          'pass' => '<<< DB PASS >>>',
 *          'db'   => '<<< DB NAME >>>',
 *          'key'  => '<<< DB AES KEY >>>', // preferred method would be to file_get_contents a file OUTSIDE of public_html here
 *      ]);
 */
class DB {
    const INSERT_SIMPLE  = 0;
    const INSERT_REPLACE = 1;
    const INSERT_UPDATE  = 2;

    protected static $conn_opts = [
        PDO::ATTR_PERSISTENT         => true,
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_WARNING,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];

    /**
     * Configuration array for server settings; each key is a name that can be passed to DB::instance.
     * Server configurations can be pre-loaded here, or configured on-the-fly by passing the connection options to DB::instance
     * Connection options for each connection:
     *  - host (optional, default=localhost)
     *  - port (optional, default=3306)
     *  - user (required)
     *  - pass (optional if user has no password)
     *  - db (optional, no default)
     *  - key (optional, no default, but the encrypt/decrypts function won't work without it)
     *    if key is provided, "SET @key=UNHEX('...');" will be run upon connection
     */
    protected static $config = [];

    /**
     * @var DB[] initialized instances of this class, keyed by configuration name
     */
    protected static $instances = [];

    /**
     * Initialize a connection (but don't actually connect) for the given configuration name
     * This function does a few different things based on the arguments:
     *  - no arguments: get the connection instance for the "default" configuration
     *  - string: get the connection instance for the specified configuration name
     *  - configuration options array: set the configuration for the "default" configuration, and get the "default" connection instance
     *  - string and conf opts array: set the configuration for the specified connection, and get that connection instance
     *
     * @param string|array|null $conn_name configuration name, or connection options array for "default" connection, or null to get an instance of the default connectin
     * @param array|null $config connection options array to set if configuration name was specified, or null to get and instance of the specified connection
     * @return DB instance of this class corresponding to the connection
     */
    public static function instance($conn_name = null, $config = null) {
        if ($conn_name === null) {
            $conn_name = 'default';
        } else if (is_array($conn_name)) {
            $config = $conn_name;
            $conn_name = 'default';
        } else {
            $conn_name = strval($conn_name);
        }

        if (!is_array($config) || (isset(static::$config[$conn_name]) && static::$config[$conn_name] == $config)) {
            $config = null;
        }

        if ($config !== null) {
            static::$config[$conn_name] = $config;
            unset(static::$instances[$conn_name]);
        }

        if (isset(static::$instances[$conn_name])) {
            return static::$instances[$conn_name];
        }

        $db = new self($conn_name);
        static::$instances[$conn_name] = $db;
        return $db;
    }

    /**
     * @var string connection config name
     */
    protected $conn_name;

    /**
     * @var PDO connection instance
     */
    protected $pdo = null;

    /**
     * @var PDOStatement[] cache of prepared statements for repeated calls to query
     */
    protected $prep_cache = [];

    /**
     * @var string AES key for local (PHP) decryption of AES_ENCRYPT'ed values
     */
    protected $aes_key = null;

    /**
     * @var string last error message from any statement
     */
    protected $last_error = null;

    protected function __construct($conn_name) {
        if (!isset(static::$config[$conn_name])) {
            throw new Exception('Invalid config name "'.$conn_name.'"');
        }

        $this->conn_name = $conn_name;

        if (empty(static::$config[$conn_name]['user'])) {
            throw new Exception('No user specified for "'.$this->conn_name.'" configuration!');
        }
    }

    /**
     * Connect to the database, set time zone and AES key if specified
     */
    protected function connect() {
        if ($this->pdo !== null) return;

        $cfg = static::$config[$this->conn_name];

        $dsn = 'mysql:';
        $dsn .= 'host='.(empty($cfg['host']) ? 'localhost' : $cfg['host']);
        $dsn .= ';port='.(empty($cfg['port']) ? 3306 : $cfg['port']);
        if (!empty($cfg['db'])) $dsn .= ';dbname='.$cfg['db'];

        $this->pdo = new PDO($dsn, $cfg['user'], empty($cfg['pass']) ? '' : $cfg['pass'], static::$conn_opts);

        $now = new DateTime();
        $mins = $now->getOffset() / 60;
        $sign = ($mins < 0 ? -1 : 1);
        $mins = abs($mins);
        $hrs = floor($mins / 60);
        $mins -= $hrs * 60;
        $offset = sprintf('%+d:%02d', $hrs * $sign, $mins);
        $this->pdo->query('SET time_zone = \''.$offset.'\'');

        if (!empty($cfg['key'])) {
            $this->pdo->query('SET @key = UNHEX(\''.$cfg['key'].'\')');
        }
    }

    /**
     * Returns the properly-encoded AES key for the encrypt/decrypt functions
     *
     * @return string AES key ready to be used in encrypt/decrypt
     * @throws Exception if no key is specified in the configuration for the connection
     */
    protected function aes_key() {
        if ($this->aes_key === null) {
            if (empty(static::$config[$this->conn_name]['key'])) {
                throw new Exception('No AES key specified for "'.$this->conn_name.'" configuration!');
            }

            $key = static::$config[$this->conn_name]['key'];
            $mysql_key = hex2bin($key);
            $new_key = str_repeat(chr(0), 16);
            for ($i=0, $len=strlen($mysql_key); $i<$len; $i++) {
                $new_key[$i % 16] = $new_key[$i % 16] ^ $mysql_key[$i];
            }
            $this->aes_key = $new_key;
        }

        return $this->aes_key;
    }

    /**
     * Returns the error from the last query, or null if there was no error.
     * Error string format is "<SQLSTATE error code>: <error message>"
     *
     * @return string|null last query error, or null
     */
    public function last_error() {
        return $this->last_error;
    }

    /**
     * Runs a query using prepared statements.
     * Returns:
     *  - On failure: FALSE
     *  - On SELECT, SHOW, EXPLAIN, or DESCRIBE: array of data, in the format specified by static::$conn_opts
     *  - On UPDATE or DELETE: integer count of rows affected
     *  - On INSERT or REPLACE: string ID of the auto-increment value of the inserted row
     *  - On anything else: TRUE
     *
     * @param string $sql SQL query to run
     * @param mixed,... arguments for the SQL query
     * @return array|int|bool|string proper return value based on the query
     */
    public function query($sql) {
        if ($this->pdo === null) $this->connect();

        $sql = trim($sql);
        $sql_sig = md5($sql);
        if (isset($this->prep_cache[$sql_sig])) {
            $stmt = $this->prep_cache[$sql_sig];
        } else {
            $stmt = $this->pdo->prepare($sql);
            $this->prep_cache[$sql_sig] = $stmt;
        }

        $args = func_get_args();
        array_shift($args);
        if (count($args) === 1 && is_array($args[0])) $args = $args[0];

        $res = $stmt->execute($args);
        if ($res === false) {
            $error_info = $stmt->errorInfo();
            $this->last_error = $error_info[0].': '.$error_info[2];
            return false;
        } else {
            $this->last_error = null;
        }

        if (preg_match('/^(?:INSERT|REPLACE)\b/i', $sql)) {
            return $this->pdo->lastInsertId();
        }
        if (preg_match('/^(?:UPDATE|DELETE)\b/i', $sql)) {
            return $stmt->rowCount();
        }
        if (preg_match('/^(?:SELECT|SHOW|EXPLAIN|DESC(?:RIBE)?)\b/i', $sql)) {
            $data = $stmt->fetchAll();
            $stmt->closeCursor();
            return $data;
        }

        return true;
    }

    /**
     * SELECT all columns from a table, optionally filtered, sorted, and paged
     *
     * @param string $table table name
     * @param int|string|array $where WHERE clause (integer for id column, raw string, or special where clause array)
     * @param string|array $order ORDER BY clause (raw string, or array of column=>direction pairs)
     * @param int $limit LIMIT for the query (# of rows per page)
     * @param int $offset OFFSET for the query (# of rows to skip)
     * @return array|false array of data, or false on failure
     */
    public function select($table, $where = [], $order = null, $limit = 0, $offset = 0) {
        $sql = 'SELECT * FROM '.static::safe_name($table);

        list($where_sql, $where_values) = static::where_to_str($where);
        $sql .= ' WHERE '.$where_sql;

        if (!empty($order)) {
            if (is_array($order)) {
                $sql .= ' ORDER BY ';
                $first = true;
                foreach ($order as $column => $dir) {
                    $dir = strtoupper(trim($dir));
                    if ($dir !== 'ASC' && $dir !== 'DESC') $dir = 'ASC';
                    if (!$first) $sql .= ', ';
                    $sql .= static::safe_name($column).' '.$dir;
                    $first = false;
                }
            } else {
                $sql .= ' ORDER BY '.$order;
            }
        }
        if ($limit > 0) $sql .= ' LIMIT '.intval($limit);
        if ($offset > 0) $sql .= ' OFFSET '.intval($offset);

        return $this->query($sql, $where_values);
    }

    /**
     * INSERT data into a table.
     * Performs a simple INSERT INTO, REPLACE INTO, or INSERT ... ON DUPLICATE KEY UPDATE based on the mode
     *
     * @param string $table table name
     * @param array $values associative array of values to insert
     * @param int $mode one of DB::INSERT_SIMPLE, DB::INSERT_REPLACE, or DB::INSERT_UPDATE
     * @return string|false string ID of the auto-increment value of the inserted row, or false on failure
     */
    public function insert($table, $values, $mode = 0 /*static::INSERT_NORMAL*/) {
        $dup_update = $mode === static::INSERT_UPDATE;

        $columns = '';
        $placeholders = '';
        $updates = '';
        $insert_values = array();
        $first = true;
        foreach ($values as $key => $value) {
            $key_safe = static::safe_name($key, false);
            if (empty($key_safe)) continue;

            if (!$first) {
                $columns .= ', ';
                $placeholders .= ', ';
            }

            $columns .= '`'.$key_safe.'`';
            $placeholders .= ':'.$key_safe;
            $insert_values[$key] = $value;

            if ($dup_update) {
                if (!$first) $updates .= ', ';
                $updates .= '`'.$key_safe.'` = VALUES(`'.$key_safe.'`)';
            }

            $first = false;
        }

        if ($first) return false;

        $sql = ($mode === static::INSERT_REPLACE ? 'REPLACE' : 'INSERT').' INTO '.static::safe_name($table).' ('.$columns.') VALUES ('.$placeholders.')';
        if ($dup_update) {
            $sql .= ' ON DUPLICATE KEY UPDATE '.$updates;
        }

        return $this->query($sql, $values);
    }

    /**
     * UPDATE data in a table.
     *
     * @param string $table table name
     * @param array $values associative array of values to update
     * @param int|string|array $where WHERE clause (integer for id column, raw string, or special where clause array)
     * @param int $limit LIMIT for the number of rows to update
     * @return int|false number of affected rows, or false on failure
     */
    public function update($table, $values, $where = [], $limit = 0) {
        $sql = 'UPDATE '.static::safe_name($table).' SET ';

        $first = true;
        foreach (array_keys($values) as $key) {
            $key_safe = static::safe_name($key, false);
            if (empty($key_safe)) continue;

            if (!$first) {
                $sql .= ', ';
            }

            $sql .= '`'.$key_safe.'` = :'.$key_safe;
            $first = false;
        }

        if ($first) return false;

        list($where_sql, $where_values) = static::where_to_str($where);
        $sql .= ' WHERE '.$where_sql;
        $values = array_merge($values, $where_values);
        if ($limit > 0) $sql .= ' LIMIT '.$limit;

        return $this->query($sql, $values);
    }

    /**
     * DELETE data from a table
     *
     * @param string $table table name
     * @param int|string|array $where WHERE clause (integer for id column, raw string, or special where clause array)
     * @param int $limit LIMIT for the number of rows to delete
     * @return int|false number of deleted rows, or false on failure
     */
    public function delete($table, $where = [], $limit = 0) {
        $sql = 'DELETE FROM '.static::safe_name($table);

        list($where_sql, $where_values) = static::where_to_str($where);
        $sql .= ' WHERE '.$where_sql;
        if ($limit > 0) $sql .= ' LIMIT '.$limit;

        return $this->query($sql, $where_values);
    }

    /**
     * Encrypts a value like MySQL's AES_ENCRYPT function.
     * Returns null for null value
     *
     * @param null|string $value value to encrypt
     * @return null|string encrypted value, or null if value is null
     */
    public function encrypt($value) {
        if ($value === null) return null;
        $padded_value = 16 - (strlen($value) % 16);
        $value = str_pad($value, (16*(floor(strlen($value) / 16)+1)), chr($padded_value));
        return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->aes_key(), $value, MCRYPT_MODE_ECB,
            mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB), MCRYPT_DEV_URANDOM));
    }

    /**
     * Decrypts a value like MySQL's AES_DECRYPT function.
     * Returns null for null value
     *
     * @param null|string $value value to decrypt
     * @return null|string decrypted value, or null if value is null
     */
    public function decrypt($value) {
        if ($value === null) return null;
        $value = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->aes_key(), $value, MCRYPT_MODE_ECB,
            mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB), MCRYPT_DEV_URANDOM));
        return rtrim($value, "\x00..\x10");
    }

    /**
     * Makes an identifier safe and optionally surrounds it with ticks.
     * Simply removes any ticks (`) and trim's the string.
     *
     * @param string $name identifier to make safe
     * @param bool $tick whether or not to surround the identifier with ticks
     * @return string safe identifier
     */
    private static function safe_name($name, $tick = true) {
        $name = str_replace('`', '', trim($name));
        if ($tick) $name = '`'.$name.'`';
        return $name;
    }

    /**
     * Parses a where clause array.
     * If the given array is a string, it is treated as a raw.
     *
     * Format for where clause array:
     * AND/OR: [ 'AND/OR', <where clause arrays>... ]
     * OPERATORS: [ '<name of column>', '<operator>', <value(s)>... ]
     *            for most operators, there is only one value, BETWEEN (and NOT BETWEEN) needs two
     *            the IN (and NOT IN) operator will take either one array as the value, or use all of the remaining array values
     *            There are two shortcuts for which an operator is not necessary: = and IN
     *            to use the shortcuts, use the following format:
     *            [ '<name of column>', <value for =, or array of values for IN> ]
     *            There is one more shortcut which allows for only an integer ID to be passed in as an integer or string,
     *            which is equivalent to using [ 'id', <ID> ] or [ 'id', '=', <ID> ]
     *            Operators are not case sensitive and will be converted to uppercase.
     *
     * Examples:
     * "x = 1 AND y < 10" => [ 'AND', [ 'x', '=', 1 ], [ 'y', '<', '10' ] ]
     * "x BETWEEN 1 AND 9 OR y = 0" => [ 'OR', [ 'x', 'BETWEEN', 1, 9 ], [ 'y', '=', 0 ] ]
     * "x IN (1, 2, 3) OR y NOT IN (4, 5, 6)" => [ 'OR', [ 'x', 'IN', [1, 2, 3] ], [ 'y', 'NOT IN', 4, 5, 6 ] ]
     * "x = 1" => [ 'x', 1 ] (using shortcut notation for =)
     * "x IN (1, 2, 3)" => [ 'x', [ 1, 2, 3 ] ] (using shortcut notation for IN)
     *
     *
     * @param string|array $where raw where string, or where clause array
     * @param int $param_count # of parameters already used in the where clause, for unique naming of parameters
     * @return array two element array: (1) where clause SQL; (2) associative array of values to include as parameters
     * @throws Exception if the where clause array is malformed
     */
    private static function where_to_str($where, $param_count = 0) {
        if (!is_array($where)) {
            if (is_int($where) || (is_string($where) && preg_match('/^-?[0-9]+$/', $where))) {
                $where = ['id', $where];
            } else {
                return [ strval($where), [] ];
            }
        }
        if (empty($where)) return [ '1', [] ];

        if (!is_string($where[0])) {
            throw new Exception('Invalid where clause! First element of where clause must be AND/OR or column name');
        }

        $group_op = strtoupper($where[0]);
        $is_group = $group_op === 'AND' || $group_op === 'OR';

        $values = [];
        if ($is_group) {
            array_shift($where);
            $where_str = '';
            $first = true;
            foreach ($where as $w) {
                list($where_sql, $where_values) = static::where_to_str($w, count($values) + $param_count);

                if (!$first) $where_str .= ' '.$group_op.' ';
                $where_str .= '('.$where_sql.')';
                if (!empty($where_values)) $values = array_merge($values, $where_values);
                $first = false;
            }
        } else {
            $where_str = static::safe_name($where[0]);

            if (count($where) === 2) {
                if (is_array($where[1])) {
                    if (!empty($where[1])) {
                        $where_str .= ' IN (';
                        $first = true;
                        foreach ($where[1] as $v) {
                            $param_name = '_where_param_'.$param_count++;

                            if (!$first) $where_str .= ', ';
                            $where_str .= ':'.$param_name;
                            $values[$param_name] = $v;
                            $first = false;
                        }
                        $where_str .= ')';
                    }
                } else {
                    $try_null_op = trim(strtoupper($where[1]));
                    if ($try_null_op === 'IS NULL' || $try_null_op === 'IS NOT NULL') {
                        $where_str .= ' '.$try_null_op;
                    } else if ($where[1] === null) {
                        $where_str .= ' IS NULL';
                    } else {
                        $where_str .= ' = :_where_param_'.$param_count;
                        $values['_where_param_'.$param_count] = $where[1];
                    }
                }
            } else if (count($where) < 3) {
                throw new Exception('Invalid where clause! Missing required arguments!');
            } else {
                $op = trim(strtoupper($where[1]));
                $where_str .= ' '.$op;

                switch ($op) {
                case '=':
                case '!=':
                case '<>':
                case '<=>':
                case '<=':
                case '>=':
                case '<':
                case '>':
                case 'LIKE':
                case 'NOT LIKE':
                case 'RLIKE':
                case 'NOT RLIKE':
                    $where_str .= ' :_where_param_'.$param_count;
                    $values['_where_param_'.$param_count] = $where[2];
                    break;
                case 'BETWEEN':
                case 'NOT BETWEEN':
                    if (count($where) < 4) {
                        throw new Exception('Not enough arguments for [NOT] BETWEEN condition!');
                    }

                    $where_str .= ' :_where_param_'.$param_count.' AND :_where_param_'.($param_count+1);
                    $values['_where_param_'.$param_count] = $where[2];
                    $values['_where_param_'.($param_count+1)] = $where[3];
                    break;
                case 'IN':
                case 'NOT IN';
                    if (is_array($where[2])) {
                        $in_values = $where[2];
                    } else {
                        $in_values = $where;
                        array_shift($in_values);
                        array_shift($in_values);
                    }
                    $where_str .= ' (';
                    foreach ($in_values as $v) {
                        $param_name = '_where_param_'.$param_count++;
                        $where_str .= ' = :'.$param_name;
                        $values[$param_name] = $v;
                    }
                    $where_str .= ')';
                    break;
                default:
                    throw new Exception('Invalid where operator ("'.$op.'")!');
                }
            }
        }

        return [ $where_str, $values ];
    }
}
