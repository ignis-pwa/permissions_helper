module.exports = class Permissions {
  constructor(file = `perm`) {
    this.loc = `${file}.sqlite`;
    this.bcrypt = require('bcrypt');
  };
  /**  
   * Add entry to the session database to store the session key.
   * @param {string} username The users username
   * @param {string} key identifying key
   * @param {number} rem Should the user be remembered
  */
  _actionLogin(username, key, rem) {
    return new Promise(async (res, rej) => {
      if (!this.sql) await this._init();
      try {
        await this.sql.run(`UPDATE users SET last_login = ${new Date().getTime()} WHERE username = "${username}"`);
        let userID = await this.sql.get(`SELECT user_id FROM users WHERE username = "${username}"`);
        await this.sql.run(`INSERT INTO user_sessions (user_id, session_key, creation_date, remember) VALUES ('${userID.user_id}', '${key}', ${new Date().getTime()}, ${rem})`);
      } catch (err) {
        rej(err)
      }
      res();
    })
  }
  /**  
   * Create database using predefined defaults.
  */
  _createDefaults() {
    return new Promise(async (res, rej) => {
      if (!this.sql) await this._init();
      await this.sql.run(`CREATE TABLE users (user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, user_password TEXT NOT NULL, date_added INTEGER, last_login INTEGER)`);
      await this.sql.run(`CREATE TABLE user_details (user_id INTEGER PRIMARY KEY, user_forename TEXT, user_surname TEXT, user_email TEXT)`);
      await this.sql.run(`CREATE TABLE user_sessions (user_id INTEGER, session_key TEXT PRIMARY KEY, creation_date INTERGER, remember INTERGER)`);
      await this.addUser('admin', 'default');
      res();
    });
  }
  /**  
   * Bind or create database.
  */
  _init() {
    return new Promise(async (res, rej) => {
      const fs = require('fs');
      const sqlite = require('sqlite');
      const reqInit = !fs.existsSync(this.loc);
      if (reqInit) await fs.writeFileSync(this.loc, "");
      this.sql = await sqlite.open(this.loc);
      if (reqInit) await this._createDefaults();
      res();
    });
  }
  /**  
   * Add a new user to the database.
   * @param {string} username The desired username
   * @param {string} password The desired password
  */
  addUser(username, password) {
    return new Promise(async (res, rej) => {
      if (!this.sql) await this._init();
      let hash = this.bcrypt.hashSync(password, 10);
      try {
        await this.sql.run(`INSERT INTO users (username, user_password, date_added, last_login) VALUES ('${username}', '${hash}', ${new Date().getTime()}, 0)`);
      } catch (err) {
        rej(err);
      }
      res();
    });
  }
  /**  
   * Checks password against database version.
   * @param {string} username The users username
   * @param {string} password The users password
   * @return {boolean} Passwords match
  */
  checkPassword(username, password) {
    return new Promise(async (res, rej) => {
      if (!this.sql) await this._init();
      const dbPassword = await this.sql.get(`SELECT user_password FROM users WHERE username = "${username}"`);
      res(this.bcrypt.compare(password, dbPassword ? dbPassword.user_password : ""));
    })
  }
  /**  
   * Changes a users password.
   * @param {string} username The users username
   * @param {string} password The users new password
  */
  updatePassword(username, password) {
    return new Promise(async (res, rej) => {
      if (!this.sql) await this._init();
      let hash = this.bcrypt.hashSync(password, 10);
      try {
        await this.sql.run(`UPDATE users SET user_password = "${hash}" WHERE username = "${username}"`);
      } catch (err) {
        rej(err)
      }
      res();
    })
  }
  /**  
   * Logs in a user if their password is correct.
   * @param {string} username The users username
   * @param {string} password The users password
   * @param {number} rem Should the user be remembered
   * @return {string} identifying key
  */
  userLogin(username, password, rem=0) {
    return new Promise(async (res, rej) => {
      if (!this.sql) await this._init();
      const valid = await this.checkPassword(username, password);
      const key = this.bcrypt.hashSync(`${password} ${new Date().getTime()}`,9)
      if (valid) {
        try {
          this._actionLogin(username, key, rem);
        } catch (err) {
          rej(err);
        }
        res(key);
      } else {
        rej('Incorrect username or password')
      }
    })
  }
}