const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');

/**  
 * Add entry to the session database to store the session key.
 * @param {string} sql Reference to database
 * @param {string} username The users username
 * @param {string} key identifying key
 * @param {number} rem Should the user be remembered
 */
const actionLogin = (sql, username, key, rem) => {
  return new Promise(async (res, rej) => {
    const update = sql.prepare('UPDATE users SET last_login = ? WHERE username = ?');
    const select = sql.prepare('SELECT user_id FROM users WHERE username = ?');
    const insert = sql.prepare('INSERT INTO user_sessions (user_id, session_key, creation_date, remember) VALUES (?, ?, ?, ?)');
    const now = new Date().getTime();
    try {
      select.get(username, (err, row) => {
        insert.run(row.user_id, key, now, rem);
      });
      update.run(now, username);
    } catch (err) {
      rej(err)
    }
    res();
  })
}

/**  
 * Add a new user to the database.
 * @param {string} sql Reference to database
 * @param {string} username The desired username
 * @param {string} password The desired password
 */
const addUser = (sql, username, password) => {
  return new Promise(async (res, rej) => {
    const salt = bcrypt.genSaltSync(9);
    const hash = bcrypt.hashSync(password, salt);
    const insert = sql.prepare('INSERT INTO users (username, user_password, date_added, last_login) VALUES (?, ?, ?, 0)')
    try {
      insert.run(username, hash, new Date().getTime());
    } catch (err) {
      rej(err);
    }
    res();
  });
}

/**  
 * Checks password against database version.
 * @param {string} sql Reference to database
 * @param {string} username The users username
 * @param {string} password The users password
 * @return {boolean} Passwords match
 */
const checkPassword = (sql, username, password) => {
  return new Promise(async (res, rej) => {
    const query = sql.prepare('SELECT user_password FROM users WHERE username = ?')
    query.get(username, (err, row) => {
      if (err) res(false)
      res(bcrypt.compare(password, row ? row.user_password : ""));
    });
  })
}

/**  
 * Initialise the database
 * @param {string} location location for permissions file
 * @return {object} Reference to database
 */
const setup = location => {
  return new Promise(async (res, rej) => {
    const sql = new sqlite3.Database(location);
    sql.serialize(() => {
      sql.run('CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, user_password TEXT NOT NULL, date_added INTEGER, last_login INTEGER)');
      sql.run('CREATE TABLE IF NOT EXISTS user_details (user_id INTEGER PRIMARY KEY, user_forename TEXT, user_surname TEXT, user_email TEXT)');
      sql.run('CREATE TABLE IF NOT EXISTS user_sessions (user_id INTEGER, session_key TEXT PRIMARY KEY, creation_date INTERGER, remember INTERGER)');
      sql.get('SELECT * FROM users', async (err, row) => {
        if (row) return
        await addUser(sql, 'admin', 'default');
      })
    })
    res(sql);
  })
}

/**  
 * Changes a users password.
 * @param {string} sql Reference to database
 * @param {string} username The users username
 * @param {string} password The users new password
 */
const updatePassword = (sql, username, password) => {
  return new Promise(async (res, rej) => {
    const salt = bcrypt.genSaltSync(9);
    const hash = bcrypt.hashSync(password, salt);
    const insert = sql.prepare('UPDATE users SET user_password = ? WHERE username = ?')
    try {
      insert.run(hash, username);
    } catch (err) {
      rej(err)
    }
    res();
  })
}

/**  
 * Logs in a user if their password is correct.
 * @param {string} sql Reference to database
 * @param {string} username The users username
 * @param {string} password The users password
 * @param {number} rem Should the user be remembered (Default: 0)
 * @return {string} identifying key
 */
const userLogin = (sql, username, password, rem = 0) => {
  return new Promise(async (res, rej) => {
    const valid = await checkPassword(sql, username, password);
    const salt = bcrypt.genSaltSync(9);
    const key = bcrypt.hashSync(`${password} ${new Date().getTime()}`, salt)
    if (valid) {
      try {
        actionLogin(sql, username, key, rem);
      } catch (err) {
        rej(err);
      }
      res(key);
    } else {
      rej('Incorrect username or password')
    }
  })
}

module.exports.actionLogin = actionLogin;
module.exports.addUser = addUser;
module.exports.checkPassword = checkPassword;
module.exports.setup = setup;
module.exports.updatePassword = updatePassword;
module.exports.userLogin = userLogin;