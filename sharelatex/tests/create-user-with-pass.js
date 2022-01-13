const minimist = require('minimist')
const { db, waitForDb } = require('../../../app/src/infrastructure/mongodb')
const UserRegistrationHandler = require('../../../app/src/Features/User/UserRegistrationHandler')

async function main() {
  await waitForDb()

  const argv = minimist(process.argv.slice(2), {
    string: ['email'],
    string: ['pass'],
    boolean: ['admin'],
  })

  const { admin, pass, email } = argv
  if (!email) {
    console.error(`Usage: node ${__filename} [--admin] --email=joe@example.com`)
    process.exit(1)
  }
  if (!pass) {
    console.error(`Usage: node ${__filename} [--admin] --pass=password`)
    process.exit(1)
  }


  await new Promise((resolve, reject) => {
    UserRegistrationHandler.registerNewUser(
      {email: email, password: pass},
      (error, user) => {
        if (error) {
          return reject(error)
        }
        db.users.updateOne(
          { _id: user._id },
          { $set: { isAdmin: admin } },
          error => {
            if (error) {
              return reject(error)
            }

            console.log('')
            console.log(`\
Successfully created ${email} as ${admin ? 'an admin' : 'a'} user.
`)
            resolve()
          }
        )
      }
    )
  })
}

main()
  .then(() => {
    console.error('Done.')
    process.exit(0)
  })
  .catch(err => {
    console.error(err)
  })