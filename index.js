const Permissions = require('./permissions_helper.js');

const ph = new Permissions();
ph.userLogin('admin', 'default', 1).then((key) => {
  console.log(`Welcome admin you secure key is ${key}`);
}).catch(err => {
  console.log(err)
})