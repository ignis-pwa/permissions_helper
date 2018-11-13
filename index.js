const ph = require('./permissions_helper');

(async _ => {
  const sql = await ph.setup('perm.db');
  ph.userLogin(sql, 'admin', 'default', 1).then(key => {
    console.log(`Welcome admin you secure key is ${key}`);
  }).catch(err => {
    console.log(err);
  })
})()