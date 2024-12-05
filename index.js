const crypto = require('crypto');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const fs = require('fs');

function iterativeHash(password, salt, iterations) {
  let hash = Buffer.from(password + salt, 'utf8');
  for (let i = 0; i < iterations; i++) {
    hash = crypto.createHash('sha1').update(hash).digest();
  }
  return hash.toString('hex');
}

function saveToFile(filename, data) {
  fs.writeFile(filename, data, (err) => {
    if (err) {
      console.error('Error saving to file:', err);
    } else {
      console.log(`Data saved to ${filename}`);
    }
  });
}

async function multiLayerHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const iterations = 100000;

  console.log('Step 1: Iterative SHA-1');
  const sha1Hash = iterativeHash(password, salt, iterations);
  console.log(`SHA-1 Hash: ${sha1Hash}`);

  console.log('Step 2: bcrypt');
  const bcryptHash = await bcrypt.hash(sha1Hash, 10);
  console.log(`bcrypt Hash: ${bcryptHash}`);

  console.log('Step 3: Argon2');
  const argon2Hash = await argon2.hash(bcryptHash);
  console.log(`Argon2 Hash: ${argon2Hash}`);

  const dataToSave = `Salt: ${salt}\nIterations: ${iterations}\nFinal Hash: ${argon2Hash}`;
  saveToFile('hashed_password.txt', dataToSave);

  return {
    salt,
    iterations,
    finalHash: argon2Hash,
  };
}

(async () => {
  const password = 'securepassword';
  const { salt, iterations, finalHash } = await multiLayerHash(password);

  console.log('\nStored Hash Information:');
  console.log(`Salt: ${salt}`);
  console.log(`Iterations: ${iterations}`);
  console.log(`Final Hash: ${finalHash}`);
})();